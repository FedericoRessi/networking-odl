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
import six
import sys
import time


class CacheEntry(collections.namedtuple('CacheEntry', ['timeout', 'value'])):

    def is_expired(self, current_clock):
        return self.timeout < current_clock


class Cache(object):

    def __init__(self, fetch_all_func):
        if not callable(fetch_all_func):
            message = 'Expected callable as parameter, got {!r}.'.format(
                fetch_all_func)
            raise TypeError(message)
        self._fetch_all = fetch_all_func
        self._entries = {}

    new_entry = CacheEntry

    def fetch(self, key, timeout):
        _, value = self.fetch_any([key], timeout=timeout)
        return value

    def fetch_any(self, keys, timeout):
        return next(self.fetch_all(keys=keys, timeout=timeout))

    def fetch_all(self, keys, timeout):
        current_clock = time.clock()
        missing_keys = []
        cause_exc_info = None
        for key in keys:
            entry = self._entries.get(key, None)
            if not entry or entry.is_expired(current_clock):
                # This has to be fetched
                missing_keys.append(key)

            else:
                # Yield existing entry
                yield key, entry.value

        if missing_keys:
            # Fetch more entries and update the cache
            try:
                new_entries_timeout = current_clock + timeout
                for key, value in self._fetch_all(tuple(missing_keys)):
                    entry = self.new_entry(new_entries_timeout, value)
                    self._entries[key] = entry

            # pylint: disable=broad-except
            except Exception:
                cause_exc_info = sys.exc_info()

            # yield new or expired entries
            for key in tuple(missing_keys):
                entry = self._entries.get(key, None)
                if entry:
                    missing_keys.remove(key)
                    yield key, entry.value

            if missing_keys:
                if not cause_exc_info:
                    try:
                        raise KeyError(
                            'Invalid keys: {!r}'.format(missing_keys))

                    except KeyError:
                        cause_exc_info = sys.exc_info()

                raise CacheFetchError(
                    missing_keys=missing_keys,
                    cause_exc_info=sys.exc_info())

    def clear(self):
        entries = self._entries
        self._entries = {}
        return entries


class CacheFetchError(KeyError):

    missing_keys = tuple()

    def __init__(self, missing_keys, cause_exc_info):
        super(CacheFetchError, self).__init__(str(cause_exc_info[0]))
        self.cause_exc_info = cause_exc_info
        self.missing_keys = missing_keys

    def reraise_cause(self):
        exc_info = self.cause_exc_info
        six.reraise(*exc_info)
