# Copyright (c) 2015-2016 OpenStack Foundation
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

import abc
import collections
import importlib
import logging

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
import six
from six.moves.urllib import parse

from networking_odl.common import cache
from networking_odl.common import client as client
from networking_odl.common import utils
from networking_odl.common._i18n import _LI, _LW, _LE


LOG = log.getLogger(__name__)


class NetworkTopologyManager(object):

    def __init__(
            self, vif_details=None, client=None, valid_vif_types=None,
            network_topology_url=None, network_topology_parsers=None):

        LOG.debug(
            'Initializing NetworkTopologyManager:\n'
            '    vif_details: %(vif_details)r\n'
            '    client: %(client)r\n'
            '    valid_vif_types: %(valid_vif_types)r\n'
            '    network_topology_url: %(network_topology_url)r\n'
            '    network_topology_parsers: %(network_topology_parsers)r',
            {'vif_details': vif_details,
             'client': client,
             'valid_vif_types': valid_vif_types,
             'network_topology_url': network_topology_url,
             'network_topology_parsers': network_topology_parsers})

        # Table of NetworkTopologyElement
        self._elements_by_ip = cache.Cache(
            self._fetch_and_parse_network_topology)

        # Details for binding port
        self._vif_details = vif_details = vif_details or {}

        # Rest client used for getting network topology from ODL
        self._client = client =\
            client or NetworkTopologyClient.create_client(
                network_topology_url=network_topology_url)

        parser_classes = NetworkTopologyParser.all_subclasses(
            parser_class_names=network_topology_parsers)
        LOG.debug('parser_classes: %r', parser_classes)

        supported_vif_types = NetworkTopologyParser.all_supported_vif_types(
            parser_classes=parser_classes)
        if not supported_vif_types:
            LOG.warning(_LW('No such supported VIF type!'))
        else:
            LOG.debug('supported_vif_types: %r', supported_vif_types)
        if valid_vif_types:
            valid_vif_types = [
                vif_type for vif_type in valid_vif_types
                if vif_type in supported_vif_types]
        else:
            # all suppported VIF types are valid
            valid_vif_types = supported_vif_types

        # Parsers used for processing network topology
        self.valid_vif_types = valid_vif_types
        if not valid_vif_types:
            LOG.warning(_LW('No such valid VIF type!'))
        else:
            LOG.debug('valid_vif_types: %r', supported_vif_types)

        self._parsers = NetworkTopologyParser.create_parsers(
            valid_vif_types=valid_vif_types,
            parser_classes=parser_classes)

    @classmethod
    def create_topology_manager(cls, vif_details=None, client=None):
        if cfg.CONF.ml2_odl.valid_vif_types:
            valid_vif_types = cfg.CONF.ml2_odl.valid_vif_types.split(',')
        else:
            valid_vif_types = []
        if cfg.CONF.ml2_odl.network_topology_parsers:
            network_topology_parsers =\
                cfg.CONF.ml2_odl.network_topology_parsers.split(',')
        else:
            network_topology_parsers = []

        return cls(
            vif_details=vif_details, client=client,
            valid_vif_types=valid_vif_types,
            network_topology_url=cfg.CONF.ml2_odl.network_topology_url,
            network_topology_parsers=network_topology_parsers)

    def bind_port(self, port_context):
        """Set binding for a valid segment

        """
        host_name = port_context.host
        elements = list()
        try:
            # Append to empty list to add as much elements as possible
            # in the case it raises an exception
            elements.extend(self._fetch_elements_by_host(host_name))
        except Exception:
            LOG.exception(
                _LE('Error fetching elements for host %(host_name)r.'),
                {'host_name': host_name})
        else:
            LOG.debug('Elements fetched from network topology: %r', elements)

        if not elements:
            # In case it wasn't able to find any network topology element
            # for given host then it uses the legacy OVS one keeping the old
            # behaviour
            LOG.warning(
                _LW('Using legacy OVS network topology element for port '
                    'binding for host: %(host_name)r.'),
                {'host_name': host_name})

            # Imported here to avoid cyclic module dependencies
            from networking_odl.ml2 import ovsdb_topology
            elements = [ovsdb_topology.OvsdbNetworkTopologyElement()]

        for vif_type in self.valid_vif_types:
            for element in elements:
                if vif_type in element.valid_vif_types:
                    # It assumes that any element could be good for given host
                    # In most of the cases I expect exactely one element for
                    # every compute host
                    try:
                        return element.bind_port(
                            port_context, vif_type, self._vif_details)

                    except Exception:
                        LOG.exception(
                            _LE('Network topology element has failed binding '
                                'port:\n%(element)s'),
                            {'element': element.to_json()})

        LOG.error(
            _LE('Unable to bind port element for given host and valid VIF '
                'types:\n'
                '\thostname: %(host_name)s\n'
                '\tvalid VIF types: %(valid_vif_types)s'),
            {'host_name': host_name,
             'valid_vif_types': ', '.join(self.valid_vif_types)})

    def _fetch_elements_by_host(self, host_name, cache_timeout=60.0):
        '''Yields all network topology elements referring to given host name

        '''

        host_addresses = [host_name]
        try:
            # It uses both compute host name and known IP addresses to
            # recognize topology elements valid for given computed host
            ip_addresses = utils.get_addresses_by_name(host_name)
        except Exception:
            ip_addresses = []
            LOG.exception(
                _LE('Unable to resolve IP addresses for host %(host_name)r'),
                {'host_name': host_name})
        else:
            host_addresses.extend(ip_addresses)

        yield_elements = set()
        try:
            for _, element in self._elements_by_ip.fetch_all(
                    host_addresses, cache_timeout):
                # yields every element only once
                if element not in yield_elements:
                    yield_elements.add(element)
                    yield element

        except cache.CacheFetchError as error:
            # This error is expected on most of the cases because typically not
            # all host_addresses maps to a network topology element.
            if yield_elements:
                # As we need only one element for every host we ignore the
                # case in which others host addresseses didn't map to any host
                LOG.debug(
                    'Host addresses not found in networking topology: %s',
                    ', '.join(error.missing_keys))
            else:
                LOG.exception(
                    _LE('No such network topology elements for given host '
                        '%(host_name)r and given IPs: %(ip_addresses)s.'),
                    {'host_name': host_name,
                     'ip_addresses': ", ".join(ip_addresses)})
                error.reraise_cause()

    def _fetch_and_parse_network_topology(self, addresses):
        # The cache calls this method to fecth new elements when at least one
        # of the addresses is not in the cache or it has expired.

        # pylint: disable=unused-argument
        LOG.info(_LI('Fetch network topology from ODL.'))
        response = self._client.get()
        response.raise_for_status()

        network_topology = response.json()
        if LOG.isEnabledFor(logging.DEBUG):
            topology_str = jsonutils.dumps(
                network_topology, sort_keys=True, indent=4,
                separators=(',', ': '))
            LOG.debug("Got network topology:\n%s", topology_str)

        at_least_one_element_for_asked_addresses = False
        for parser in self._parsers:
            try:
                for element in parser.parse_network_topology(network_topology):
                    if not isinstance(element, NetworkTopologyElement):
                        raise TypeError(
                            "Yield element doesn't implement interface "
                            "'NetworkTopologyElement': {!r}".format(element))
                    # the same element can be known by more host addresses
                    for host_address in element.host_addresses:
                        if host_address in addresses:
                            at_least_one_element_for_asked_addresses = True
                        yield host_address, element
            except Exception:
                LOG.exception(
                    _LE("Parser %(parser)r failed to parse network topology."),
                    {'parser': parser})

        if not at_least_one_element_for_asked_addresses:
            # this will mark entries for given addresses as failed to allow
            # calling this method again as soon it is requested and avoid
            # waiting for cache expiration
            raise ValueError(
                'No such topology element for given host addresses: {}'.format(
                    ', '.join(addresses)))


@six.add_metaclass(abc.ABCMeta)
class NetworkTopologyParser(object):

    # List of class names of registered implementations of interface
    # NetworkTopologyParser
    all_subclasse_names = [
        'networking_odl.ml2.ovsdb_topology:OvsdbNetworkTopologyParser']

    # Mapping name to class of pre-load parser classes
    _all_subclasses = collections.OrderedDict()

    @abc.abstractproperty
    @classmethod
    def supported_vif_types(cls):
        'List of VIF types supported by this parser class'

    @abc.abstractmethod
    def parse_network_topology(self, network_topology):
        '''Parses OpenDaylight network topology

        Yields all network topology elements implementing
        'NetworkTopologyElement' interface found in given network topology.
        '''

    @classmethod
    def all_subclasses(cls, parser_class_names=None):
        parser_class_names = parser_class_names or cls.all_subclasse_names
        return list(
            cls._iter_subclasses(parser_class_names=parser_class_names))

    @classmethod
    def _iter_subclasses(cls, parser_class_names):
        '''Iterates over all registered implementations of the interface.

        '''
        for parser_class_name in parser_class_names:
            try:
                yield cls.subclass_from_name(parser_class_name)
            except Exception:
                LOG.exception(
                    _LE('Invalid subclass name: %r'), parser_class_name)

    @classmethod
    def all_supported_vif_types(cls, parser_classes=None):
        # Using an ordered dict to keep the order and assure every entry
        # is contained only once.
        supported_vif_types = collections.OrderedDict()
        for subclass in parser_classes or cls.all_subclasses():
            for vif_type in subclass.supported_vif_types:
                supported_vif_types[vif_type] = None
        return list(supported_vif_types)

    @classmethod
    def create_parsers(cls, valid_vif_types, parser_classes=None):
        '''Creates and registers parsers of classes

        Yields only parsers the support al least one of given valid VIF types
        '''

        # valid VIF type.
        for subclass in parser_classes or cls.all_subclasses():
            try:
                if set(valid_vif_types) & set(subclass.supported_vif_types):
                    yield subclass()
                else:
                    LOG.info(
                        _LI("Parser class %(parser_class_name)r doens't "
                            "support any valid VIF type: %(valid_vif_types)s"),
                        {'parser_class_name': subclass.__name__,
                         'valid_vif_types': ', '.join(valid_vif_types)})
            except Exception:
                LOG.exception(
                    _LE('Error creating networking topology parser of class '
                        '%(parser_class)r'),
                    {'parser_class': subclass.__name__})

    @classmethod
    def subclass_from_name(cls, subclass_name):
        subclass = cls._all_subclasses.get(subclass_name)
        if subclass is None:
            module_name, class_name = subclass_name.rsplit(':', 1)
            module = importlib.import_module(module_name)
            subclass = getattr(module, class_name, None)
            if subclass is None:
                raise ValueError(
                    "Class {class_name!r} not defined in module "
                    "{module_name!r}.".format(
                        class_name=class_name, module_name=module_name))

            if not issubclass(subclass, cls):
                raise TypeError(
                    "Class {class_name!r} of module {module_name!r} is not "
                    "a subclass of {this_class_name!r}.".format(
                        class_name=class_name, module_name=module_name,
                        this_class_name=cls.__name__))

            LOG.info(_LI("Network topology parser class imported: %r"),
                     subclass_name)
            cls._all_subclasses[subclass_name] = subclass
        return subclass


@six.add_metaclass(abc.ABCMeta)
class NetworkTopologyElement(object):

    @abc.abstractproperty
    def host_addresses(self):
        '''List of known host addresses of a single compute host

        Either host names and ip addresses are valid.
        Neutron host controller must know at least one of these compute host
        names or ip addresses to find this element.
        '''

    @abc.abstractproperty
    def valid_vif_types(self):
        '''Returns a tuple listing VIF types supported by the compute node

        '''

    @abc.abstractmethod
    def bind_port(self, port_context, vif_type, vif_details):
        '''Bind port context using given vif type and vit details

        This method is expected to search for a valid segment and then
        call following method:

            from neutron.common import constants
            from neutron.plugins.ml2 import driver_api

            port_context.set_binding(
                valid_segment[driver_api.ID], vif_type, vif_details,
                status=constants.PORT_STATUS_ACTIVE)

        '''

    def to_dict(self):
        cls = type(self)
        return {
            'class': cls.__module__ + '.' + cls.__name__,
            'host_addresses': list(self.host_addresses),
            'valid_vif_types': list(self.valid_vif_types)}

    def to_json(self):
        return jsonutils.dumps(
            self.to_dict(), sort_keys=True, indent=4, separators=(',', ': '))


class NetworkTopologyClient(client.OpenDaylightRestClient):

    _GET_ODL_NETWORK_TOPOLOGY_URL =\
        'restconf/operational/network-topology:network-topology'

    def __init__(
            self, url, username, password, timeout, network_topology_url=None):
        if not network_topology_url:
            if url:
                url = parse.urlparse(url)
                port = ''
                if url.port:
                    port = ':' + str(url.port)
                network_topology_url =\
                    '{}://{}{}/{}'.format(
                        url.scheme, url.hostname, port,
                        self._GET_ODL_NETWORK_TOPOLOGY_URL)

        super(NetworkTopologyClient, self).__init__(
            url=network_topology_url, username=username, password=password,
            timeout=timeout)
