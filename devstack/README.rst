======================
 Enabling in Devstack
======================

1. Download DevStack

2. Copy the sample local.conf over::

     cp devstack/local.conf.example local.conf

3. Optionally, to manually configure this:

   Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-odl http://git.openstack.org/openstack/networking-odl

4. Optionally, to enable support for OpenDaylight L3 router functionality, add the
   below::

     > cat local.conf
     [[local|localrc]]
     ODL_L3=True

5. If you need to route the traffic out of the box (e.g. br-ex), set
   ODL_PROVIDER_MAPPINGS to map the interface, as shown below::

     > cat local.conf
     [[local|localrc]]
     ODL_L3=True
     ODL_PROVIDER_MAPPINGS=${ODL_PROVIDER_MAPPINGS:-br-ex:eth2}

6. Optionally, to enable support for OpenDaylight with LBaaS V2, add this::

     > cat local.conf
     [[local|localrc]]
     enable_plugin neutron-lbaas http://git.openstack.org/openstack/neutron-lbaas
     enable_service q-lbaasv2
     NEUTRON_LBAAS_SERVICE_PROVIDERV2="LOADBALANCERV2:opendaylight:networking_odl.lbaas.driver_v2.OpenDaylightLbaasDriverV2:default"

7. run ``stack.sh``

8. Note: In a multi-node devstack environment, for each compute node you will want to add this
   to the local.conf file::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-odl http://git.openstack.org/openstack/networking-odl
     ODL_MODE=compute

9. Note: In a node using a release of Open vSwitch provided from another source
   than your Linux distribution you have to enable in your local.conf skipping
   of OVS installation step by setting *SKIP_OVS_INSTALL=True*. For example when
   stacking together with `networking-ovs-dpdk
   <https://github.com/openstack/networking-ovs-dpdk/>`_ Neutron plug-in to
   avoid conflicts between openvswitch and ovs-dpdk you have to add this to
   the local.conf file::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-ovs-dpdk http://git.openstack.org/openstack/networking-ovs-dpdk
     enable_plugin networking-odl http://git.openstack.org/openstack/networking-odl
     SKIP_OVS_INSTALL=True
     Q_ML2_PLUGIN_MECHANISM_DRIVERS=opendaylight

10. Configure port binding

The network port binding for spawned VMs can be implemented by more (virtual)
switch implementations. The way network ports are binded to virtual network
can be restricted configuring a list of knwon VIF types. Known valid vif types
are for example 'ovs' and 'vhostuser'. You can specify this ordered list by
editing 'ODL_VALID_VIF_TYPES' variable in the local.conf file::

     > cat local.conf
     [[local|localrc]]
     ODL_VALID_VIF_TYPES=vhostuser,ovs

Port binding is performed detecting VIF types supported by compute host where
new virtual machine is going to be spawn. Host capabilities are inferred by
parsing network topology fetched from OpenDayligh using following URL:

http://<odl-server-ip>:<port>/restconf/operational/network-topology:network-topology

where odl-server-ip could be for example 192.168.2.10 and port 8087. This URL
can be changed editing local.conf::

     > cat local.conf
     [[local|localrc]]
     ODL_NETWORK_TOPOLOGY_URL="http://192.168.2.10:8087/restconf/operational/network-topology:network-topology"

By the default above URL is obtained from the URL networking-odl is configured
to connect to OpenDaylight north bound.

Network topology is parsed to detect supported VIF type by a list of pluggable
network topology parsers. These parsers are created starting from a list of
know class names implementing NetworkTopologyParser interface.
You can specify this ordered list by editing 'ODL_NETWORK_TOPOLOGY_PARSERS'
variable in the local.conf file::

     > cat local.conf
     [[local|localrc]]
     ODL_NETWORK_TOPOLOGY_PARSERS=networking_odl.ml2.ovsdb_topology:OvsdbNetworkTopologyParser
