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


import mock

from neutron.tests import base

from networking_odl.common import utils


class TestGetAddressesByName(base.DietTestCase):

    # pylint: disable=protected-access, unused-argument

    def setUp(self):
        super(TestGetAddressesByName, self).setUp()
        self.clear_cache()
        self.addCleanup(self.clear_cache)
        time = self.patch(
            utils.cache, 'time', clock=mock.Mock(return_value=0.0))
        self.clock = time.clock
        socket = self.patch(utils, 'socket')
        self.getaddrinfo = socket.getaddrinfo

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        mocked = context.start()
        self.addCleanup(context.stop)
        return mocked

    def clear_cache(self):
        utils._addresses_by_name_cache.clear()

    def test_get_addresses_by_valid_name(self):
        self.getaddrinfo.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 0)),
            (2, 2, 17, '', ('127.0.0.1', 0)),
            (2, 3, 0, '', ('127.0.0.1', 0)),
            (2, 1, 6, '', ('10.237.214.247', 0)),
            (2, 2, 17, '', ('10.237.214.247', 0)),
            (2, 3, 0, '', ('10.237.214.247', 0))]

        # When valid host name is requested
        result = utils.get_addresses_by_name('some_host_name')

        # Then correct addresses are returned
        self.assertEqual(('10.237.214.247', '127.0.0.1'), result)

        # Then fetched addresses are cached
        self.assertIs(result, utils.get_addresses_by_name('some_host_name'))

        # Then addresses are fetched only once
        self.getaddrinfo.assert_called_once_with('some_host_name', None)

    def test_get_addresses_by_valid_name_when_cache_expires(self):
        self.getaddrinfo.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 0)),
            (2, 2, 17, '', ('127.0.0.1', 0)),
            (2, 3, 0, '', ('127.0.0.1', 0)),
            (2, 1, 6, '', ('10.237.214.247', 0)),
            (2, 2, 17, '', ('10.237.214.247', 0)),
            (2, 3, 0, '', ('10.237.214.247', 0))]

        # When valid host name is requested
        result1 = utils.get_addresses_by_name('some_host_name')

        # and after a long time
        self.clock.return_value = 1.0e6

        # When valid host name is requested
        result2 = utils.get_addresses_by_name('some_host_name')

        # Then correct addresses are returned
        self.assertEqual(('10.237.214.247', '127.0.0.1'), result1)
        self.assertEqual(('10.237.214.247', '127.0.0.1'), result2)

        # Then addresses are fetched only once
        self.getaddrinfo.assert_has_calls(
            [mock.call('some_host_name', None),
             mock.call('some_host_name', None)])

    def test_get_addresses_by_invalid_name(self):

        # Given addresses resolution is failing
        def failing_getaddrinfo(name, service):
            raise RuntimeError()

        self.getaddrinfo.side_effect = failing_getaddrinfo

        # When invalid name is requested
        self.assertRaises(
            RuntimeError, utils.get_addresses_by_name, 'some_host_name')

        # When invalid name is requested again
        self.assertRaises(
            RuntimeError, utils.get_addresses_by_name, 'some_host_name')

        # Then result is fetched more times
        self.getaddrinfo.assert_has_calls(
            [mock.call('some_host_name', None),
             mock.call('some_host_name', None)])

    def test_get_addresses_failing_when_expired_in_cache(self):
        self.getaddrinfo.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 0)),
            (2, 2, 17, '', ('127.0.0.1', 0)),
            (2, 3, 0, '', ('127.0.0.1', 0)),
            (2, 1, 6, '', ('10.237.214.247', 0)),
            (2, 2, 17, '', ('10.237.214.247', 0)),
            (2, 3, 0, '', ('10.237.214.247', 0))]

        # Given valid result is in chache but expired
        given_previous_result = utils.get_addresses_by_name('some_host_name')
        self.clock.return_value = 1.0e6

        # Given addresses resolution is now failing
        def failing_getaddrinfo(name, service):
            raise RuntimeError()

        self.getaddrinfo.side_effect = failing_getaddrinfo

        result = utils.get_addresses_by_name('some_host_name')

        # Then correct addresses are returned
        self.assertEqual(('10.237.214.247', '127.0.0.1'), result)

        # Then fetched addresses are the same expired ones
        self.assertIs(given_previous_result, result)

        # Then result is fetched more times
        self.getaddrinfo.assert_has_calls(
            [mock.call('some_host_name', None),
             mock.call('some_host_name', None)])
