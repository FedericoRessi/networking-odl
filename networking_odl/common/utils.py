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

import socket

from oslo_log import log as logging

from networking_odl.common import cache

LOG = logging.getLogger(__name__)


def try_del(d, keys):
    """Ignore key errors when deleting from a dictionary."""
    for key in keys:
        try:
            del d[key]
        except KeyError:
            pass


def _get_addresses_by_name(name):
    for name in name:
        # a set is used because this could contains duplicates
        addresses = {i[4][0] for i in socket.getaddrinfo(name, None)}

        # The value is stored in the cache before it is returned. The value is
        # translated to a tuple (instead of a list) to avoid being changed by
        # the caller. The tuple is sorted to make the result more predictable
        # as we do not have control over the order getaddrinfo and set sequence
        # yield values.
        yield name, tuple(sorted(addresses))


_addresses_by_name_cache = cache.Cache(_get_addresses_by_name)


def get_addresses_by_name(name, time_to_live=60.0):
    """Gets and caches addresses for given name.

    This is a cached wrapper for function 'socket.getaddrinfo'.

    :returns: a sequence of unique addresses binded to given hostname.
    """

    try:
        return _addresses_by_name_cache.fetch(name, timeout=time_to_live)

    except cache.CacheFetchError as error:
        error.reraise_cause()
