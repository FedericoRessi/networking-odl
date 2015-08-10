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
from six.moves.urllib import parse as urlparse

from neutron.extensions import portbindings
from oslo_log import log as logging
from oslo_serialization import jsonutils

from networking_odl.common import cache
from networking_odl.common import utils
from networking_odl.openstack.common._i18n import _LE
from networking_odl.openstack.common._i18n import _LI


LOG = logging.getLogger(__name__)


_GET_ODL_NETWORK_TOPOLOGY_URL =\
    'restconf/operational/network-topology:network-topology/'


UNKNOWN = None


class NetworkTopology(object):

    def __init__(self, client):
        self._client = client
        # Tables of NetworkTopologyElement
        self._elements_by_ip = cache.Cache(self._fetch_topology_from_odl)

    def fetch_element_by_host(self, host_name, cache_timeout=60.0):
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
        response = self._client.get(_GET_ODL_NETWORK_TOPOLOGY_URL)

        json_network_topology = response.json()
        if LOG.isEnabledFor(logging.logging.DEBUG):
            topology_str = jsonutils.dumps(
                json_network_topology, sort_keys=True, indent=4,
                separators=(',', ': '))
            LOG.debug("Got network topology:\n%s", topology_str)

        return _parse_network_topology(json_network_topology)


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
        datapath_type = node.get("ovsdb:datapath-type", UNKNOWN)
        if datapath_type == "ovsdb:datapath-type-netdev":
            element.has_datapath_type_netdev = True
            LOG.debug(
                'Topology element updated:\n'
                ' - uuid: %(uuid)r\n'
                ' - has_datapath_type_netdev: %(has_datapath_type_netdev)r',
                {'uuid': uuid,
                 'has_datapath_type_netdev': element.has_datapath_type_netdev})


class NetworkTopologyElement(object):

    remote_ip = UNKNOWN  # it can be UNKNOWN or a string
    has_datapath_type_netdev = False  # it can be False or True
    support_vhost_user = False  # it can be False or True

    @property
    def vif_type(self):
        if self.has_datapath_type_netdev and self.support_vhost_user:
            return portbindings.VIF_TYPE_VHOST_USER

        else:
            return portbindings.VIF_TYPE_OVS
