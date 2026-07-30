:tocdepth: 3

policy/misc/zeromq-multi-host-auto-setup.zeek
=============================================
.. zeek:namespace:: Cluster::Backend::ZeroMQ

This script interrogates the Cluster::nodes content to configure
the XPUB/XSUB connect and listen endpoints by assuming that the
manager node runs the XPUB/XSUB proxy thread using ports 5555 and 5556.
Ports are configurable via ZEEK_CLUSTER_BACKEND_ZEROMQ_XPUB_PORT
and ZEEK_CLUSTER_BACKEND_ZEROMQ_XSUB_PORT environment variables.

If you do not run the XPUB/XSUB proxy in the manager node, this script
is not useful and you'll need to whip up your own.

:Namespace: Cluster::Backend::ZeroMQ
:Imports: :doc:`policy/frameworks/cluster/backend/zeromq </scripts/policy/frameworks/cluster/backend/zeromq/index>`

Summary
~~~~~~~
Redefinitions
#############
=================================================================================================== =
:zeek:id:`Cluster::Backend::ZeroMQ::connect_xpub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::Backend::ZeroMQ::connect_xsub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::Backend::ZeroMQ::ipv6`: :zeek:type:`bool` :zeek:attr:`&redef`
:zeek:id:`Cluster::Backend::ZeroMQ::listen_xpub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`
:zeek:id:`Cluster::Backend::ZeroMQ::listen_xsub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`
=================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

