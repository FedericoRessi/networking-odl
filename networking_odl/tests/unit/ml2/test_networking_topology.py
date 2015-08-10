# Copyright (c) 2015 OpenStack Foundation
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

from os import path

import mock
from oslo_log import log as logging
from oslo_serialization import jsonutils
import requests

from neutron.common import constants as n_constants
from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.tests import base

from networking_odl.ml2 import mech_driver
from networking_odl.ml2 import network_topology


LOG = logging.getLogger(__name__)


class TestNetworkingTopology(base.DietTestCase):

    # pylint: disable=protected-access

    # given valid  and invalid segments
    valid_segment = {
        api.ID: 'API_ID',
        api.NETWORK_TYPE: constants.TYPE_LOCAL,
        api.SEGMENTATION_ID: 'API_SEGMENTATION_ID',
        api.PHYSICAL_NETWORK: 'API_PHYSICAL_NETWORK'}

    invalid_segment = {
        api.ID: 'API_ID',
        api.NETWORK_TYPE: constants.TYPE_NONE,
        api.SEGMENTATION_ID: 'API_SEGMENTATION_ID',
        api.PHYSICAL_NETWORK: 'API_PHYSICAL_NETWORK'}

    segments_to_bind = [valid_segment, invalid_segment]

    def setUp(self):
        super(TestNetworkingTopology, self).setUp()
        self.patch(network_topology.LOG, 'isEnabledFor', lambda level: True)

    def test_fetch_element_with_no_entry(self):
        given_client = self.mock_client('topology_without_vhost_user')
        self.mock_get_addresses_by_name(['192.168.0.1'])
        given_network_topology = network_topology.NetworkTopology(
            client=given_client)

        self.assertRaises(
            KeyError,
            lambda: given_network_topology._fetch_element_by_host(
                'some_host_name.'))

    def test_fetch_element_with_ovs_entry(self):
        given_client = self.mock_client('topology_without_vhost_user')
        self.mock_get_addresses_by_name(['10.237.214.247'])
        given_network_topology = network_topology.NetworkTopology(
            client=given_client)

        element = given_network_topology._fetch_element_by_host(
            'some_host_name.')

        self.assertEqual('10.237.214.247', element.remote_ip)
        self.assertIs(portbindings.VIF_TYPE_OVS, element.vif_type)

    def test_fetch_element_with_vhost_user_entry(self):
        given_client = self.mock_client('topology_with_vhost_user')
        self.mock_get_addresses_by_name(['192.168.66.1'])
        given_network_topology = network_topology.NetworkTopology(
            client=given_client)

        element = given_network_topology._fetch_element_by_host(
            'some_host_name.')

        self.assertEqual('192.168.66.1', element.remote_ip)
        self.assertIs(portbindings.VIF_TYPE_VHOST_USER, element.vif_type)

    def mock_get_addresses_by_name(self, ips):
        return self.patch(
            network_topology, 'utils',
            mock.Mock(
                get_addresses_by_name=mock.Mock(return_value=tuple(ips))))

    def mock_client(self, topology_name):

        cached_file_path = path.join(
            path.dirname(__file__), topology_name + '.json')

        with open(cached_file_path, 'rt') as fd:
            topology = jsonutils.load(fd, encoding='utf-8')

        mocked_client = mock.NonCallableMock(
            specs=network_topology.NetworkTopologyClient)
        mocked_client.get().json.return_value = topology

        return mocked_client

    @mock.patch.object(network_topology, 'cfg')
    def test_get_vif_type(self, cfg):
        # pylint: disable=unused-argument
        given_port_context = mock.MagicMock(spec=api.PortContext)
        given_topology = network_topology.NetworkTopology()

        # when getting VIF type
        vif_type = given_topology._get_vif_type(given_port_context)

        # then VIF type is ovs
        self.assertIs(vif_type, portbindings.VIF_TYPE_OVS)

    def test_is_valid_segment(self):
        """Validate the _check_segment method."""

        # given driver and all network types
        given_topology = network_topology.NetworkTopology()
        all_network_types = [constants.TYPE_FLAT, constants.TYPE_GRE,
                             constants.TYPE_LOCAL, constants.TYPE_VXLAN,
                             constants.TYPE_VLAN, constants.TYPE_NONE]

        # when checking segments network type
        valid_types = {
            network_type
            for network_type in all_network_types
            if given_topology._is_valid_segment(
                {api.NETWORK_TYPE: network_type})}

        # then true is returned only for valid network types
        self.assertEqual({
            constants.TYPE_LOCAL, constants.TYPE_GRE, constants.TYPE_VXLAN,
            constants.TYPE_VLAN}, valid_types)

    @mock.patch.object(network_topology.NetworkTopology, '_get_vif_type')
    def test_bind_port_front_end(self, _get_vif_type):
        given_front_end = mech_driver.OpenDaylightMechanismDriver()
        given_port_context = self.given_port_context()
        given_back_end = mech_driver.OpenDaylightDriver()
        _get_vif_type.return_value = "EXPECTED_VIF_TYPE"
        given_front_end.odl_drv = given_back_end

        # when port is bound
        given_front_end.bind_port(given_port_context)

        # then vif type is got calling _get_vif_type
        _get_vif_type.assert_called_once_with(given_port_context.host)

        # then context binding is setup wit returned vif_type and valid
        # segment api ID
        given_port_context.set_binding.assert_called_once_with(
            self.valid_segment[api.ID], 'EXPECTED_VIF_TYPE',
            given_back_end.vif_details, status=n_constants.PORT_STATUS_ACTIVE)

    def test_bind_port_back_end_with_vif_type_ovs(self):
        self._test_bind_port(portbindings.VIF_TYPE_OVS)

    def test_bind_port_back_end_with_vif_type_vhost_user(self):
        self._test_bind_port(
            portbindings.VIF_TYPE_VHOST_USER,
            {'vhostuser_ovs_plug': True,
             'vhostuser_socket': '/var/run/openvswitch/vhuCURRENT_CON',
             'vhostuser_mode': 'client'})

    def test_bind_port_without_valid_segment(self):
        self.segments_to_bind = [self.invalid_segment]
        self._test_bind_port(portbindings.VIF_TYPE_OVS)

    def _test_bind_port(
            self, given_vif_type, expected_additional_vif_details=None):
        given_port_context = self.given_port_context()
        given_topology = network_topology.NetworkTopology()
        given_topology._get_vif_type = mock.Mock(return_value=given_vif_type)

        # when port is bound
        given_topology.bind_port(given_port_context)

        if self.valid_segment in self.segments_to_bind:
            # then vif type is got calling _get_vif_type
            given_topology._get_vif_type.assert_called_once_with(
                given_port_context.host)

            expected_vif_details = dict(given_topology._vif_details)
            if expected_additional_vif_details:
                expected_vif_details.update(expected_additional_vif_details)

            # then context binding is setup wit returned vif_type and valid
            # segment api ID
            given_port_context.set_binding.assert_called_once_with(
                self.valid_segment[api.ID], given_vif_type,
                expected_vif_details, status=n_constants.PORT_STATUS_ACTIVE)

        else:
            self.assertFalse(given_topology._get_vif_type.called)
            self.assertFalse(given_port_context.set_binding.called)

    def given_port_context(self):
        # given NetworkContext
        network = mock.MagicMock(spec=api.NetworkContext)

        # given port context
        return mock.MagicMock(
            spec=driver_context.PortContext,
            current={'id': 'CURRENT_CONTEXT_ID'},
            segments_to_bind=self.segments_to_bind,
            network=network)

    def test_get_vif_type_without_vhost_user(self):
        vif_type = self._test_get_vif_type(
            'topology_without_vhost_user', ('10.237.214.247',))
        self.assertIs(vif_type, portbindings.VIF_TYPE_OVS)

    def test_get_vif_type_with_vhost_user(self):
        vif_type = self._test_get_vif_type(
            'topology_with_vhost_user', ('192.168.66.1',))
        self.assertIs(vif_type, portbindings.VIF_TYPE_VHOST_USER)

    def _test_get_vif_type(
            self, mocked_topology_name, mocked_ip_addresses):
        request = self.mock_request_network_topology(mocked_topology_name)
        get_addresses_by_name = self.patch(
            network_topology.utils, 'get_addresses_by_name',
            return_value=mocked_ip_addresses)

        given_topology = network_topology.NetworkTopology()

        # when getting VIF type
        vif_type = given_topology._get_vif_type('my_host_name')

        # then IP addresses are fetched
        get_addresses_by_name.assert_called_once_with('my_host_name')

        # then topology has been fetched
        request.assert_called_once_with(
            method='GET', url=self.NETOWORK_TOPOLOGY_URL, data=None,
            headers={'Content-Type': 'application/json'},
            auth=('admin', 'admin'), timeout=5)

        return vif_type

    NETOWORK_TOPOLOGY_URL =\
        'http://localhost:8181/'\
        'restconf/operational/network-topology:network-topology/'

    def mock_request_network_topology(self, file_name):
        # patch given configuration
        mocked_cfg = self.patch(network_topology, 'cfg')
        mocked_cfg.CONF.ml2_odl.url =\
            'http://localhost:8181/controller/nb/v2/neutron'
        mocked_cfg.CONF.ml2_odl.username = 'admin'
        mocked_cfg.CONF.ml2_odl.password = 'admin'
        mocked_cfg.CONF.ml2_odl.timeout = 5

        cached_file_path = path.join(
            path.dirname(__file__), file_name + '.json')

        if path.isfile(cached_file_path):
            LOG.debug('Loading topology from file: %r', cached_file_path)
            with open(cached_file_path, 'rt') as fd:
                topology = jsonutils.load(fd, encoding='utf-8')

        else:
            LOG.debug(
                'Getting topology from ODL: %r', self.NETOWORK_TOPOLOGY_URL)
            request = requests.get(
                self.NETOWORK_TOPOLOGY_URL, auth=('admin', 'admin'),
                headers={'Content-Type': 'application/json'})
            request.raise_for_status()

            with open(cached_file_path, 'wt') as fd:
                LOG.debug('Saving topology to file: %r', cached_file_path)
                topology = request.json()
                jsonutils.dump(
                    topology, fd, sort_keys=True, indent=4,
                    separators=(',', ': '))

        mocked_request = self.patch(
            mech_driver.odl_client.requests, 'request',
            return_value=mock.MagicMock(
                spec=requests.Response,
                json=mock.MagicMock(return_value=topology)))

        return mocked_request

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        patch = context.start()
        self.addCleanup(context.stop)
        return patch


class TestNetworkTopologyClient(base.DietTestCase):

    given_host = 'given.host'
    given_port = 1234
    given_url_with_port = 'http://{}:{}/'.format(
        given_host, given_port)
    given_url_without_port = 'http://{}/'.format(given_host)
    given_username = 'GIVEN_USERNAME'
    given_password = 'GIVEN_PASSWORD'
    given_timeout = 20

    def given_client(
            self, url=None, username=None, password=None, timeout=None):
        return network_topology.NetworkTopologyClient(
            base_url=url or self.given_url_with_port,
            username=username or self.given_username,
            password=password or self.given_password,
            timeout=timeout or self.given_timeout)

    def test_constructor(self):
        # When client is created
        rest_client = network_topology.NetworkTopologyClient(
            base_url=self.given_url_with_port,
            username=self.given_username,
            password=self.given_password,
            timeout=self.given_timeout)

        self.assertEqual(self.given_url_with_port, rest_client.base_url)
        self.assertEqual(
            (self.given_username, self.given_password), rest_client.auth)
        self.assertEqual(self.given_timeout, rest_client.timeout)

    def test_request_with_port(self):
        # Given rest client and used 'requests' module
        given_client = self.given_client()
        mocked_requests_module = self.mocked_requests()

        # When a request is performed
        result = given_client.request(
            'GIVEN_METHOD', 'given/path', 'GIVEN_DATA')

        # Then request method is called
        mocked_requests_module.request.assert_called_once_with(
            auth=(self.given_username, self.given_password),
            data='GIVEN_DATA', headers={'Content-Type': 'application/json'},
            method='GIVEN_METHOD', timeout=self.given_timeout,
            url='http://{}:{}/given/path'.format(
                self.given_host, self.given_port))

        # Then request method result is returned
        self.assertIs(mocked_requests_module.request.return_value, result)

    def test_request_without_port(self):
        # Given rest client and used 'requests' module
        given_client = self.given_client(url=self.given_url_without_port)
        mocked_requests_module = self.mocked_requests()

        # When a request is performed
        result = given_client.request(
            'GIVEN_METHOD', 'given/path', 'GIVEN_DATA')

        # Then request method is called
        mocked_requests_module.request.assert_called_once_with(
            auth=(self.given_username, self.given_password),
            data='GIVEN_DATA', headers={'Content-Type': 'application/json'},
            method='GIVEN_METHOD', timeout=self.given_timeout,
            url='http://{}/given/path'.format(self.given_host))

        # Then request method result is returned
        self.assertIs(mocked_requests_module.request.return_value, result)

    def test_get(self):
        # Given rest client and used 'requests' module
        given_client = self.given_client()
        mocked_requests_module = self.mocked_requests()

        # When a request is performed
        result = given_client.get('given/path', 'GIVEN_DATA')

        # Then request method is called
        mocked_requests_module.request.assert_called_once_with(
            auth=(self.given_username, self.given_password),
            data='GIVEN_DATA', headers={'Content-Type': 'application/json'},
            method='GET', timeout=self.given_timeout,
            url='http://{}:{}/given/path'.format(
                self.given_host, self.given_port))

        # Then request method result is returned
        self.assertIs(mocked_requests_module.request.return_value, result)

    def mocked_requests(self):
        return self.patch(network_topology, 'requests')

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        mocked = context.start()
        self.addCleanup(context.stop)
        return mocked


class TestNetworkingTopologyElement(base.DietTestCase):

    def given_element(
            self, has_datapath_type_netdev, support_vhost_user):
        element = network_topology.NetworkTopologyElement()
        element.has_datapath_type_netdev = has_datapath_type_netdev
        element.support_vhost_user = support_vhost_user
        return element

    def test_vif_type_with_any_negative_value(self):
        self.assertIs(
            portbindings.VIF_TYPE_OVS, self.given_element(
                has_datapath_type_netdev=False, support_vhost_user=False
            ).vif_type)

        self.assertIs(
            portbindings.VIF_TYPE_OVS, self.given_element(
                has_datapath_type_netdev=True, support_vhost_user=False
            ).vif_type)

        self.assertIs(
            portbindings.VIF_TYPE_OVS, self.given_element(
                has_datapath_type_netdev=False, support_vhost_user=True
            ).vif_type)

    def test_vif_type_with_all_positive_values(self):
        self.assertIs(
            portbindings.VIF_TYPE_VHOST_USER, self.given_element(
                has_datapath_type_netdev=True, support_vhost_user=True
            ).vif_type)
