# Copyright (c) 2014 Red Hat Inc.
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

# Python framework
import requests

# 3rd party and portability libraries
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
import six.moves.urllib.parse as urlparse


LOG = logging.getLogger(__name__)


class OpenDaylightRestClient(object):

    @classmethod
    def create_client(cls):
        return cls(
            cfg.CONF.ml2_odl.url,
            cfg.CONF.ml2_odl.username,
            cfg.CONF.ml2_odl.password,
            cfg.CONF.ml2_odl.timeout)

    def __init__(self, url, username, password, timeout):
        self.url = url
        self.timeout = timeout
        self.auth = (username, password)

    def sendjson(self, method, urlpath, obj):
        """Send json to the OpenDaylight controller."""

        headers = {'Content-Type': 'application/json'}
        data = jsonutils.dumps(obj, indent=2) if obj else None
        url = '/'.join([self.url, urlpath])
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(obj)s)",
                  {'method': method, 'url': url, 'obj': obj})
        r = requests.request(method, url=url,
                             headers=headers, data=data,
                             auth=self.auth, timeout=self.timeout)
        r.raise_for_status()

    def try_delete(self, urlpath):
        try:
            self.sendjson('delete', urlpath, None)
        except requests.HTTPError as e:
            # The resource is already removed. ignore 404 gracefully
            if e.response.status_code != 404:
                raise
            LOG.debug("%(urlpath)s doesn't exist", {'urlpath': urlpath})
            return False
        return True

    def get(self, full_path, data=None):
        return self.request('GET', full_path, data)

    def request(self, method, full_path, data=None):
        headers = {'Content-Type': 'application/json'}
        url = self.root_url + full_path
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(data)s)",
                  {'method': method, 'url': url, 'data': data})
        response = requests.request(
            method=method, url=url, headers=headers, data=data, auth=self.auth,
            timeout=self.timeout)
        response.raise_for_status()
        return response

    _root_url = None

    @property
    def root_url(self):
        root_url = self._root_url
        if root_url is None:
            url = urlparse.urlparse(self.url)
            port = ''
            if url.port:
                port = ':' + str(url.port)
            else:
                port = ''
            self._root_url = root_url = '{}://{}{}/'.format(
                url.scheme, url.hostname, port)
        return root_url
