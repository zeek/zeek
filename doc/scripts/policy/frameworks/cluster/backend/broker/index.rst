:orphan:

Package: policy/frameworks/cluster/backend/broker
=================================================


:doc:`/scripts/policy/frameworks/cluster/backend/broker/__load__.zeek`


:doc:`/scripts/policy/frameworks/cluster/backend/broker/main.zeek`

   Broker cluster backend support.

   The Broker cluster backend is a peer-to-peer backend that has been
   in use since Bro 2.6 and the default until Zeek 8.1. Cluster nodes peer
   with each other selectively, using a fixed connection strategy based on
   cluster node types. This information is stored in :zeek:see:`Cluster::nodes`
   as populated by the cluster-layout.zeek file, or internally via the Supervisor
   when in use.

   Conceptually:

     * All nodes peer with all logger nodes
     * All worker nodes peer with all proxy nodes and the manager node
     * All proxy nodes peer with the manager

   This implies that logger, manager and proxy nodes are all listening
   on the ports defined in the cluster layout.

   Note that publish-subscribe visibility with Broker is limited to nodes
   that are directly peered. A worker publishing a message to a topic another
   worker node is subscribed to will not be visible by the other worker.

:doc:`/scripts/policy/frameworks/cluster/backend/broker/backpressure.zeek`


:doc:`/scripts/policy/frameworks/cluster/backend/broker/telemetry.zeek`


