:tocdepth: 3

base/bif/messaging.bif.zeek
===========================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions for peering and various messaging patterns.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Functions
#########
======================================================= ===================================================================
:zeek:id:`Broker::__flush_logs`: :zeek:type:`function`  
:zeek:id:`Broker::__forward`: :zeek:type:`function`     
:zeek:id:`Broker::__publish_id`: :zeek:type:`function`  
:zeek:id:`Broker::__subscribe`: :zeek:type:`function`   
:zeek:id:`Broker::__unsubscribe`: :zeek:type:`function` 
:zeek:id:`Broker::make_event`: :zeek:type:`function`    Create a data structure that may be used to send a remote event via
                                                        :zeek:see:`Broker::publish`.
:zeek:id:`Broker::publish`: :zeek:type:`function`       Publishes an event at a given topic.
======================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::__flush_logs
   :source-code: base/bif/messaging.bif.zeek 37 37

   :Type: :zeek:type:`function` () : :zeek:type:`count`


.. zeek:id:: Broker::__forward
   :source-code: base/bif/messaging.bif.zeek 46 46

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__publish_id
   :source-code: base/bif/messaging.bif.zeek 40 40

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, id: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__subscribe
   :source-code: base/bif/messaging.bif.zeek 43 43

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__unsubscribe
   :source-code: base/bif/messaging.bif.zeek 49 49

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::make_event
   :source-code: base/bif/messaging.bif.zeek 22 22

   :Type: :zeek:type:`function` (...) : :zeek:type:`Broker::Event`

   Create a data structure that may be used to send a remote event via
   :zeek:see:`Broker::publish`.
   

   :param args: an event, followed by a list of argument values that may be used
         to call it.
   

   :returns: opaque communication data that may be used to send a remote
            event.

.. zeek:id:: Broker::publish
   :source-code: base/bif/messaging.bif.zeek 34 34

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event at a given topic.
   

   :param topic: a topic associated with the event message.
   

   :param args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.


