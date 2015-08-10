# Copyright (c) 2013-2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import copy
import os

import requests
from six.moves.urllib import parse as urlparse

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from networking_odl.common import cache
from networking_odl.common import utils
from networking_odl.openstack.common._i18n import _LE
from networking_odl.openstack.common._i18n import _LI
from networking_odl.openstack.common._i18n import _LW


LOG = logging.getLogger(__name__)


# default location for vhostuser sockets
VHOSTUSER_SOCKET_DIR = '/var/run/openvswitch'

# prefix for ovs port
PORT_PREFIX = 'vhu'


_GET_ODL_NETWORK_TOPOLOGY_URL =\
    'restconf/operational/network-topology:network-topology/'


class NetworkTopology(object):

    def __init__(self, vif_details=None, client=None):
        self._vif_details = vif_details or {}
        self._client = client

        # Tables of NetworkTopologyElement
        self._elements_by_ip = cache.Cache(self._fetch_topology_from_odl)

    @property
    def client(self):
        client = self._client
        if not client:
            self._client = client = NetworkTopologyClient.from_configuration()
        return client

    def bind_port(self, port_context):
        """Set binding for valid segment

        """

        # Bind port to the first valid segment
        for segment in port_context.segments_to_bind:
            if self._is_valid_segment(segment):
                # Guest best VIF type for given host
                vif_type = self._get_vif_type(port_context.host)
                vif_details = self._get_vif_details(
                    port_context.current['id'], vif_type)
                LOG.debug(
                    'Bind port with valid segment:\n'
                    '\tport: %(port)r\n'
                    '\tnetwork: %(network)r\n'
                    '\tsegment: %(segment)r\n'
                    '\tVIF type: %(vif_type)r\n'
                    '\tVIF details: %(vif_details)r',
                    {'port': port_context.current['id'],
                     'network': port_context.network.current['id'],
                     'segment': segment, 'vif_type': vif_type,
                     'vif_details': vif_details})
                port_context.set_binding(
                    segment[driver_api.ID], vif_type, vif_details,
                    status=n_const.PORT_STATUS_ACTIVE)
                break

        else:
            LOG.warning(
                _LW('No such valid segment for binding given port:\n'
                    '\tport: %(port)r\n'
                    '\tnetwork: %(network)r\n'),
                {'port': port_context.current['id'],
                 'network': port_context.network.current['id']})

    def _is_valid_segment(self, segment):
        """Verify a segment is valid for the OpenDaylight MechanismDriver.

        Verify the requested segment is supported by ODL and return True or
        False to indicate this to callers.
        """

        network_type = segment[driver_api.NETWORK_TYPE]
        return network_type in [constants.TYPE_LOCAL, constants.TYPE_GRE,
                                constants.TYPE_VXLAN, constants.TYPE_VLAN]

    def _get_vif_type(self, host_name):
        """Get VIF type string for given PortContext

        Dummy implementation: it always returns following constant.
        neutron.extensions.portbindings.VIF_TYPE_OVS
        """
        # pylint: disable=broad-except

        vif_type = portbindings.VIF_TYPE_OVS

        try:
            element = self._fetch_element_by_host(host_name)
            vif_type = element.vif_type

        except Exception:
            LOG.exception(_LE('Unable to detect VIF type.'))

        return vif_type

    def _get_vif_details(self, port_context_id, vif_type):
        vif_details = copy.copy(self._vif_details)
        if vif_type == portbindings.VIF_TYPE_VHOST_USER:
            socket_path = os.path.join(
                VHOSTUSER_SOCKET_DIR, (PORT_PREFIX + port_context_id)[:14])

            vif_details.update({
                portbindings.VHOST_USER_MODE:
                portbindings.VHOST_USER_MODE_CLIENT,
                portbindings.VHOST_USER_OVS_PLUG: True,
                portbindings.VHOST_USER_SOCKET: socket_path
            })
        return vif_details

    def _fetch_element_by_host(self, host_name, cache_timeout=60.0):
        host_ips = utils.get_addresses_by_name(host_name)
        try:
            _, element = self._elements_by_ip.fetch_any(
                host_ips, cache_timeout)

        except cache.CacheFetchError as error:
            LOG.error(
                _LE('Error getting network topology for hostname '
                    '%(host_name)r.'),
                {'host_name': host_name},
                exc_info=error.cause_exc_info)
            error.reraise_cause()

        return element

    def _fetch_topology_from_odl(self, ips):
        # pylint: disable=unused-argument
        LOG.info(_LI('Fetch network topology from ODL.'))
        response = self.client.get(_GET_ODL_NETWORK_TOPOLOGY_URL)

        json_network_topology = response.json()
        if LOG.isEnabledFor(logging.logging.DEBUG):
            topology_str = jsonutils.dumps(
                json_network_topology, sort_keys=True, indent=4,
                separators=(',', ': '))
            LOG.debug("Got network topology:\n%s", topology_str)

        return _parse_network_topology(json_network_topology)


class NetworkTopologyClient(object):

    def __init__(self, base_url, username, password, timeout):
        self.base_url = base_url
        self.auth = (username, password)
        self.timeout = timeout

    @classmethod
    def from_configuration(cls):
        # Parse connection configuration
        url = urlparse.urlparse(cfg.CONF.ml2_odl.url)
        port = ''
        if url.port:
            port = ':' + str(url.port)
        base_url = '{}://{}{}/'.format(url.scheme, url.hostname, port)

        return cls(
            base_url=base_url,
            username=cfg.CONF.ml2_odl.username,
            password=cfg.CONF.ml2_odl.password,
            timeout=cfg.CONF.ml2_odl.timeout)

    def get(self, full_path, data=None):
        return self.request('GET', full_path, data)

    def request(self, method, full_path, data=None):
        headers = {'Content-Type': 'application/json'}
        url = self.base_url + full_path
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(data)s)",
                  {'method': method, 'url': url, 'data': data})
        response = requests.request(
            method=method, url=url, headers=headers, data=data, auth=self.auth,
            timeout=self.timeout)
        response.raise_for_status()
        return response


def _parse_network_topology(network_topologies):
    elements_by_uuid = collections.defaultdict(NetworkTopologyElement)

    for topology in network_topologies[
            'network-topology']['topology']:
        if topology['topology-id'].startswith('ovsdb:'):
            for node in topology['node']:
                # expected url format: ovsdb://uuid/<uuid>[/<path>]]
                node_url = urlparse.urlparse(node['node-id'])
                if node_url.scheme == 'ovsdb'\
                        and node_url.netloc == 'uuid':
                    # split_res = ['', '<uuid>', '<path>']
                    split_res = node_url.path.split('/', 2)

                    # uuid is used to identify nodes referring to the same
                    # element
                    uuid = split_res[1]
                    element = elements_by_uuid[uuid]

                    # inner_path can be [] or [<path>]
                    inner_path = split_res[2:]
                    _update_element_from_json_ovsdb_topology_node(
                        node, element, uuid, *inner_path)

    # Yield results always in the same order to enforce reliability:
    # the order of parsed topology nodes yields same elements in the same
    # order
    for uuid in sorted(elements_by_uuid):
        element = elements_by_uuid[uuid]
        yield element.remote_ip, element


def _update_element_from_json_ovsdb_topology_node(
        node, element, uuid, path=None):

    if not path:
        # global element section (root path)

        # fetch remote IP address
        element.remote_ip = node["ovsdb:connection-info"]["remote-ip"]

        for vif_type_entry in node.get(
                "ovsdb:interface-type-entry", []):
            if vif_type_entry.get("interface-type", None) ==\
                    "ovsdb:interface-type-dpdkvhostuser":
                element.support_vhost_user = True
                break

        else:
            LOG.debug(
                'Interface type not found in network topology node %r.', uuid)

        LOG.debug(
            'Topology element updated:\n'
            ' - uuid: %(uuid)r\n'
            ' - remote_ip: %(remote_ip)r\n'
            ' - support_vhost_user: %(support_vhost_user)r',
            {'uuid': uuid,
             'remote_ip': element.remote_ip,
             'support_vhost_user': element.support_vhost_user})

    elif path == 'bridge/br-int':
        datapath_type = node.get("ovsdb:datapath-type")
        if datapath_type == "ovsdb:datapath-type-netdev":
            element.has_datapath_type_netdev = True
            LOG.debug(
                'Topology element updated:\n'
                ' - uuid: %(uuid)r\n'
                ' - has_datapath_type_netdev: %(has_datapath_type_netdev)r',
                {'uuid': uuid,
                 'has_datapath_type_netdev': element.has_datapath_type_netdev})


class NetworkTopologyElement(object):

    remote_ip = None  # it can be None or a string
    has_datapath_type_netdev = False  # it can be False or True
    support_vhost_user = False  # it can be False or True

    @property
    def vif_type(self):
        if self.has_datapath_type_netdev and self.support_vhost_user:
            return portbindings.VIF_TYPE_VHOST_USER

        else:
            return portbindings.VIF_TYPE_OVS
