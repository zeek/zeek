:tocdepth: 3

base/bif/messaging.bif.zeek
===========================
.. zeek:namespace:: Broker
.. zeek:namespace:: Cluster
.. zeek:namespace:: GLOBAL

Functions for peering and various messaging patterns.

:Namespaces: Broker, Cluster, GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ===================================================================
:zeek:id:`Broker::__auto_publish`: :zeek:type:`function`   
:zeek:id:`Broker::__auto_unpublish`: :zeek:type:`function` 
:zeek:id:`Broker::__flush_logs`: :zeek:type:`function`     
:zeek:id:`Broker::__forward`: :zeek:type:`function`        
:zeek:id:`Broker::__publish_id`: :zeek:type:`function`     
:zeek:id:`Broker::__subscribe`: :zeek:type:`function`      
:zeek:id:`Broker::__unsubscribe`: :zeek:type:`function`    
:zeek:id:`Broker::make_event`: :zeek:type:`function`       Create a data structure that may be used to send a remote event via
                                                           :zeek:see:`Broker::publish`.
:zeek:id:`Broker::publish`: :zeek:type:`function`          Publishes an event at a given topic.
:zeek:id:`Cluster::publish_hrw`: :zeek:type:`function`     Publishes an event to a node within a pool according to Rendezvous
                                                           (Highest Random Weight) hashing strategy.
:zeek:id:`Cluster::publish_rr`: :zeek:type:`function`      Publishes an event to a node within a pool according to Round-Robin
                                                           distribution strategy.
========================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::__auto_publish

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, ev: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__auto_unpublish

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, ev: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__flush_logs

   :Type: :zeek:type:`function` () : :zeek:type:`count`


.. zeek:id:: Broker::__forward

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__publish_id

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, id: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__subscribe

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__unsubscribe

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::make_event

   :Type: :zeek:type:`function` (...) : :zeek:type:`Broker::Event`

   Create a data structure that may be used to send a remote event via
   :zeek:see:`Broker::publish`.
   

   :args: an event, followed by a list of argument values that may be used
         to call it.
   

   :returns: opaque communication data that may be used to send a remote
            event.

.. zeek:id:: Broker::publish

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event at a given topic.
   

   :topic: a topic associated with the event message.
   

   :args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. zeek:id:: Cluster::publish_hrw

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Rendezvous
   (Highest Random Weight) hashing strategy.
   

   :pool: the pool of nodes that are eligible to receive the event.
   

   :key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.
   

   :args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. zeek:id:: Cluster::publish_rr

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Round-Robin
   distribution strategy.
   

   :pool: the pool of nodes that are eligible to receive the event.
   

   :key: an arbitrary string to identify the purpose for which you're
        distributing the event.  e.g. consider using namespacing of your
        script like "Intel::cluster_rr_key".
   

   :args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.


