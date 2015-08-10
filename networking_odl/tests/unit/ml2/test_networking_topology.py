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

from neutron.extensions import portbindings
from neutron.tests import base

from networking_odl.common import client
from networking_odl.ml2 import network_topology


LOG = logging.getLogger(__name__)


class TestNetworkingTopology(base.DietTestCase):

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
            lambda: given_network_topology.fetch_element_by_host(
                'some_host_name.'))

    def test_fetch_element_with_ovs_entry(self):
        given_client = self.mock_client('topology_without_vhost_user')
        self.mock_get_addresses_by_name(['10.237.214.247'])
        given_network_topology = network_topology.NetworkTopology(
            client=given_client)

        element = given_network_topology.fetch_element_by_host(
            'some_host_name.')

        self.assertEqual('10.237.214.247', element.remote_ip)
        self.assertIs(portbindings.VIF_TYPE_OVS, element.vif_type)

    def test_fetch_element_with_vhost_user_entry(self):
        given_client = self.mock_client('topology_with_vhost_user')
        self.mock_get_addresses_by_name(['192.168.66.1'])
        given_network_topology = network_topology.NetworkTopology(
            client=given_client)

        element = given_network_topology.fetch_element_by_host(
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
            specs=client.OpenDaylightRestClient)
        mocked_client.get().json.return_value = topology

        return mocked_client

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        patch = context.start()
        self.addCleanup(context.stop)
        return patch


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
