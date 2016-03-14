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

from oslo_config import cfg

odl_opts = [
    cfg.StrOpt('url',
               help=_("HTTP URL of OpenDaylight REST interface.")),
    cfg.StrOpt('username',
               help=_("HTTP username for authentication")),
    cfg.StrOpt('password', secret=True,
               help=_("HTTP password for authentication")),
    cfg.IntOpt('timeout', default=10,
               help=_("HTTP timeout in seconds.")),
    cfg.IntOpt('session_timeout', default=30,
               help=_("Tomcat session timeout in minutes.")),
    cfg.IntOpt('sync_timeout', default=10,
               help=_("(V2 driver) Sync thread timeout in seconds.")),
    cfg.IntOpt('retry_count', default=5,
               help=_("(V2 driver) Number of times to retry a row "
                      "before failing.")),
    cfg.BoolOpt('enable_lightweight_testing',
                default=False,
                help='Test without real ODL'),

    # Port binding options
    cfg.StrOpt(
        name='valid_vif_types',
        help=_("List of VIF types valid for port binding: ovs, "
               "vhostuser, etc.")),
    cfg.StrOpt(
        'network_topology_url',
        help=_("Http URL to fetch network topology from ODL.")),
    cfg.StrOpt(
        name='network_topology_parsers',
        help=_("List of knwon network topology parser implementation "
               "classes.")),
]

cfg.CONF.register_opts(odl_opts, "ml2_odl")
