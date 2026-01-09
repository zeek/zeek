:tocdepth: 3

policy/frameworks/cluster/experimental.zeek
===========================================
.. zeek:namespace:: Cluster::Experimental

Experimental features of the Cluster framework.

:Namespace: Cluster::Experimental
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~
Events
######
========================================================================== =======================================================================
:zeek:id:`Cluster::Experimental::cluster_started`: :zeek:type:`event`      When using broker-enabled cluster framework, this event will be
                                                                           broadcasted from the manager once all nodes reported that they have set
                                                                           up all their outgoing connections to other cluster nodes based on the
                                                                           given cluster layout.
:zeek:id:`Cluster::Experimental::node_fully_connected`: :zeek:type:`event` When using broker-enabled cluster framework, this event will be sent to
                                                                           the manager and raised locally, once a cluster node has successfully
                                                                           conducted cluster-level handshakes for all its outgoing connections to
                                                                           other cluster nodes based on the given cluster layout.
========================================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Cluster::Experimental::cluster_started
   :source-code: policy/frameworks/cluster/nodes-experimental/manager.zeek 33 36

   :Type: :zeek:type:`event` ()

   When using broker-enabled cluster framework, this event will be
   broadcasted from the manager once all nodes reported that they have set
   up all their outgoing connections to other cluster nodes based on the
   given cluster layout.

   .. warning::

       There is no tracking of cluster node connectivity. Thus, there is
       no guarantee that all peerings still exist at the time of this event
       being raised.

.. zeek:id:: Cluster::Experimental::node_fully_connected
   :source-code: policy/frameworks/cluster/nodes-experimental/manager.zeek 16 31

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`, resending: :zeek:type:`bool`)

   When using broker-enabled cluster framework, this event will be sent to
   the manager and raised locally, once a cluster node has successfully
   conducted cluster-level handshakes for all its outgoing connections to
   other cluster nodes based on the given cluster layout.


   :param name: The name of the now fully connected node.


   :param id: The identifier of the now fully connected node.


   :param resending: If true, the node has previously signaled that it is fully
              connected. This may happen in case the manager restarts.

   .. warning::

       There is no tracking of cluster node connectivity. Thus, there is
       no guarantee that all peerings still exist at the time of this event
       being raised.


