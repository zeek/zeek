:tocdepth: 3

base/frameworks/cluster/pubsub.zeek
===================================
.. zeek:namespace:: Cluster


:Namespace: Cluster
:Imports: :doc:`base/bif/cluster.bif.zeek </scripts/base/bif/cluster.bif.zeek>`, :doc:`base/frameworks/cluster/types.zeek </scripts/base/frameworks/cluster/types.zeek>`

Summary
~~~~~~~
Hooks
#####
===================================================== =============================================================
:zeek:id:`Cluster::on_subscribe`: :zeek:type:`hook`   A hook invoked for every :zeek:see:`Cluster::subscribe` call.
:zeek:id:`Cluster::on_unsubscribe`: :zeek:type:`hook` A hook invoked for every :zeek:see:`Cluster::subscribe` call.
===================================================== =============================================================

Functions
#########
====================================================== =================================
:zeek:id:`Cluster::subscribe`: :zeek:type:`function`   Subscribe to the given topic.
:zeek:id:`Cluster::unsubscribe`: :zeek:type:`function` Unsubscribe from the given topic.
====================================================== =================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Hooks
#####
.. zeek:id:: Cluster::on_subscribe
   :source-code: base/frameworks/cluster/pubsub.zeek 27 27

   :Type: :zeek:type:`hook` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   A hook invoked for every :zeek:see:`Cluster::subscribe` call.

   Breaking from this hook has no effect.


   :param topic: The topic string as given to :zeek:see:`Cluster::subscribe`.

.. zeek:id:: Cluster::on_unsubscribe
   :source-code: base/frameworks/cluster/pubsub.zeek 34 34

   :Type: :zeek:type:`hook` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   A hook invoked for every :zeek:see:`Cluster::subscribe` call.

   Breaking from this hook has no effect.


   :param topic: The topic string as given to :zeek:see:`Cluster::subscribe`.

Functions
#########
.. zeek:id:: Cluster::subscribe
   :source-code: base/frameworks/cluster/pubsub.zeek 41 44

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   Subscribe to the given topic.


   :param topic: The topic to subscribe to.


   :returns: T on success, else F.

.. zeek:id:: Cluster::unsubscribe
   :source-code: base/frameworks/cluster/pubsub.zeek 46 49

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`) : :zeek:type:`bool`

   Unsubscribe from the given topic.


   :param topic: The topic to unsubscribe from.


   :returns: T on success, else F.


