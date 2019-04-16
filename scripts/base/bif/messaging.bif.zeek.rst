:tocdepth: 3

base/bif/messaging.bif.zeek
===========================
.. bro:namespace:: Broker
.. bro:namespace:: Cluster
.. bro:namespace:: GLOBAL

Functions for peering and various messaging patterns.

:Namespaces: Broker, Cluster, GLOBAL

Summary
~~~~~~~
Functions
#########
======================================================== ===================================================================
:bro:id:`Broker::__auto_publish`: :bro:type:`function`   
:bro:id:`Broker::__auto_unpublish`: :bro:type:`function` 
:bro:id:`Broker::__flush_logs`: :bro:type:`function`     
:bro:id:`Broker::__forward`: :bro:type:`function`        
:bro:id:`Broker::__publish_id`: :bro:type:`function`     
:bro:id:`Broker::__subscribe`: :bro:type:`function`      
:bro:id:`Broker::__unsubscribe`: :bro:type:`function`    
:bro:id:`Broker::make_event`: :bro:type:`function`       Create a data structure that may be used to send a remote event via
                                                         :bro:see:`Broker::publish`.
:bro:id:`Broker::publish`: :bro:type:`function`          Publishes an event at a given topic.
:bro:id:`Cluster::publish_hrw`: :bro:type:`function`     Publishes an event to a node within a pool according to Rendezvous
                                                         (Highest Random Weight) hashing strategy.
:bro:id:`Cluster::publish_rr`: :bro:type:`function`      Publishes an event to a node within a pool according to Round-Robin
                                                         distribution strategy.
======================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Broker::__auto_publish

   :Type: :bro:type:`function` (topic: :bro:type:`string`, ev: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__auto_unpublish

   :Type: :bro:type:`function` (topic: :bro:type:`string`, ev: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__flush_logs

   :Type: :bro:type:`function` () : :bro:type:`count`


.. bro:id:: Broker::__forward

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Broker::__publish_id

   :Type: :bro:type:`function` (topic: :bro:type:`string`, id: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Broker::__subscribe

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Broker::__unsubscribe

   :Type: :bro:type:`function` (topic_prefix: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Broker::make_event

   :Type: :bro:type:`function` (...) : :bro:type:`Broker::Event`

   Create a data structure that may be used to send a remote event via
   :bro:see:`Broker::publish`.
   

   :args: an event, followed by a list of argument values that may be used
         to call it.
   

   :returns: opaque communication data that may be used to send a remote
            event.

.. bro:id:: Broker::publish

   :Type: :bro:type:`function` (...) : :bro:type:`bool`

   Publishes an event at a given topic.
   

   :topic: a topic associated with the event message.
   

   :args: Either the event arguments as already made by
         :bro:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. bro:id:: Cluster::publish_hrw

   :Type: :bro:type:`function` (...) : :bro:type:`bool`

   Publishes an event to a node within a pool according to Rendezvous
   (Highest Random Weight) hashing strategy.
   

   :pool: the pool of nodes that are eligible to receive the event.
   

   :key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.
   

   :args: Either the event arguments as already made by
         :bro:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. bro:id:: Cluster::publish_rr

   :Type: :bro:type:`function` (...) : :bro:type:`bool`

   Publishes an event to a node within a pool according to Round-Robin
   distribution strategy.
   

   :pool: the pool of nodes that are eligible to receive the event.
   

   :key: an arbitrary string to identify the purpose for which you're
        distributing the event.  e.g. consider using namespacing of your
        script like "Intel::cluster_rr_key".
   

   :args: Either the event arguments as already made by
         :bro:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.


