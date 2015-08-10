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

import unittest

import mock

from networking_odl.common import client


class TestOpenDaylightRestClient(unittest.TestCase):

    given_host = 'given.host'
    given_port = 1234
    given_url_with_port = 'http://{}:{}/some/path'.format(
        given_host, given_port)
    given_url_without_port = 'http://{}/some/path'.format(given_host)
    given_username = 'GIVEN_USERNAME'
    given_password = 'GIVEN_PASSWORD'
    given_timeout = 20

    def given_client(
            self, url=None, username=None, password=None, timeout=None):
        return client.OpenDaylightRestClient(
            url=url or self.given_url_with_port,
            username=username or self.given_username,
            password=password or self.given_password,
            timeout=timeout or self.given_timeout)

    def test_constructor(self):
        # When client is created
        rest_client = client.OpenDaylightRestClient(
            url=self.given_url_with_port,
            username=self.given_username,
            password=self.given_password,
            timeout=self.given_timeout)

        # Then root URL is extracted from given URL
        self.assertEqual(
            'http://{}:{}/'.format(self.given_host, self.given_port),
            rest_client.root_url)

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
        return self.patch(client, 'requests')

    def patch(self, target, name, *args, **kwargs):
        context = mock.patch.object(target, name, *args, **kwargs)
        mocked = context.start()
        self.addCleanup(context.stop)
        return mocked
