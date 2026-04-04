:tocdepth: 3

base/bif/cluster.bif.zeek
=========================
.. zeek:namespace:: Cluster
.. zeek:namespace:: Cluster::Backend
.. zeek:namespace:: GLOBAL


:Namespaces: Cluster, Cluster::Backend, GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===================================
:zeek:id:`Cluster::Backend::error`: :zeek:type:`event` Generated on cluster backend error.
====================================================== ===================================

Functions
#########
============================================================= ===================================================================
:zeek:id:`Cluster::Backend::__init`: :zeek:type:`function`    Initialize the global cluster backend.
:zeek:id:`Cluster::__listen_websocket`: :zeek:type:`function`
:zeek:id:`Cluster::__subscribe`: :zeek:type:`function`
:zeek:id:`Cluster::__unsubscribe`: :zeek:type:`function`
:zeek:id:`Cluster::make_event`: :zeek:type:`function`         Create a data structure that may be used to send a remote event via
                                                              :zeek:see:`Broker::publish`.
:zeek:id:`Cluster::publish`: :zeek:type:`function`            Publishes an event to a given topic.
:zeek:id:`Cluster::publish_hrw`: :zeek:type:`function`        Publishes an event to a node within a pool according to Rendezvous
                                                              (Highest Random Weight) hashing strategy.
:zeek:id:`Cluster::publish_rr`: :zeek:type:`function`         Publishes an event to a node within a pool according to Round-Robin
                                                              distribution strategy.
============================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Cluster::Backend::error
   :source-code: base/frameworks/cluster/main.zeek 546 550

   :Type: :zeek:type:`event` (tag: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated on cluster backend error.


   :param tag: A structured tag, not further specified.


   :param message: A free form message with more details about the error.

Functions
#########
.. zeek:id:: Cluster::Backend::__init
   :source-code: base/bif/cluster.bif.zeek 48 48

   :Type: :zeek:type:`function` (nid: :zeek:type:`string`) : :zeek:type:`bool`

   Initialize the global cluster backend.


   :returns: true on success.

.. zeek:id:: Cluster::__listen_websocket
   :source-code: base/bif/cluster.bif.zeek 87 87

   :Type: :zeek:type:`function` (options: :zeek:type:`Cluster::WebSocketServerOptions`) : :zeek:type:`bool`


.. zeek:id:: Cluster::__subscribe
   :source-code: base/bif/cluster.bif.zeek 39 39

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Cluster::__unsubscribe
   :source-code: base/bif/cluster.bif.zeek 42 42

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Cluster::make_event
   :source-code: base/bif/cluster.bif.zeek 36 36

   :Type: :zeek:type:`function` (...) : :zeek:type:`Cluster::Event`

   Create a data structure that may be used to send a remote event via
   :zeek:see:`Broker::publish`.


   :param args: an event, followed by a list of argument values that may be used
         to call it.


   :returns: A :zeek:type:`Cluster::Event` instance that can be published via
            :zeek:see:`Cluster::publish`, :zeek:see:`Cluster::publish_rr`
            or :zeek:see:`Cluster::publish_hrw`.

.. zeek:id:: Cluster::publish
   :source-code: base/bif/cluster.bif.zeek 24 24

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a given topic.


   :param topic: a topic associated with the event message.


   :param args: Either the event arguments as already made by
         :zeek:see:`Cluster::make_event` or the argument list to pass along
         to it.


   :returns: T if the event was accepted for sending. Depending on
            the selected cluster backend, an event may be dropped
            when a Zeek cluster is overloadede. This can happen on
            the sending or receiving node.

.. zeek:id:: Cluster::publish_hrw
   :source-code: base/bif/cluster.bif.zeek 84 84

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Rendezvous
   (Highest Random Weight) hashing strategy.


   :param pool: the pool of nodes that are eligible to receive the event.


   :param key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.


   :param args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.


   :returns: true if the message is sent.

.. zeek:id:: Cluster::publish_rr
   :source-code: base/bif/cluster.bif.zeek 67 67

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Round-Robin
   distribution strategy.


   :param pool: the pool of nodes that are eligible to receive the event.


   :param key: an arbitrary string to identify the purpose for which you're
        distributing the event.  e.g. consider using namespacing of your
        script like "Intel::cluster_rr_key".


   :param args: Either the event arguments as already made by
         :zeek:see:`Cluster::make_event` or the argument list to pass along
         to it.


   :returns: true if the message is sent.


