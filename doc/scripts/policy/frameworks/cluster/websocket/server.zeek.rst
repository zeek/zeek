:tocdepth: 3

policy/frameworks/cluster/websocket/server.zeek
===============================================

Script to load for running a single WebSocket server.

This script is mostly meant for ad-hoc testing. In a Zeekctl environment,
the ``UseWebSocket`` option should be used instead.

Note that if :zeek:see:`Cluster::backend` is ``CLUSTER_BACKEND_NONE`` at the
time this script is loaded, it loads the ZeroMQ cluster backend and starts a
locally running XPUB/XSUB proxy thread. If you instead want to use Broker's hub
functionality instead, load policy/frameworks/cluster/backend/broker before
loading this script.

Note also that this script will raise a fatal error if the cluster backend
is :zeek:see:`Cluster::CLUSTER_BACKEND_NONE`, but :zeek:see:`Cluster::nodes`
is populated with entries.

:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`, :doc:`policy/frameworks/cluster/backend/zeromq </scripts/policy/frameworks/cluster/backend/zeromq/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================================ =
:zeek:id:`Cluster::Backend::ZeroMQ::run_proxy_thread`: :zeek:type:`bool` :zeek:attr:`&redef` 
============================================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

