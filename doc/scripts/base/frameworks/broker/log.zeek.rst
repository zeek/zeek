:tocdepth: 3

base/frameworks/broker/log.zeek
===============================
.. zeek:namespace:: Broker


:Namespace: Broker
:Imports: :doc:`base/frameworks/broker/main.zeek </scripts/base/frameworks/broker/main.zeek>`

Summary
~~~~~~~
Types
#####
============================================== =============================================================
:zeek:type:`Broker::Info`: :zeek:type:`record` A record type containing the column fields of the Broker log.
:zeek:type:`Broker::Type`: :zeek:type:`enum`   The type of a Broker activity being logged.
============================================== =============================================================

Redefinitions
#############
======================================= =====================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The Broker logging stream identifier.
                                        
                                        * :zeek:enum:`Broker::LOG`
======================================= =====================================

Hooks
#####
=========================================================== =============================================
:zeek:id:`Broker::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=========================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Broker::Info
   :source-code: base/frameworks/broker/log.zeek 21 33

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The network time at which a Broker event occurred.

      ty: :zeek:type:`Broker::Type` :zeek:attr:`&log`
         The type of the Broker event.

      ev: :zeek:type:`string` :zeek:attr:`&log`
         The event being logged.

      peer: :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&log` :zeek:attr:`&optional`
         The peer (if any) with which a Broker event is
         concerned.

      message: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         An optional message describing the Broker event in more detail

   A record type containing the column fields of the Broker log.

.. zeek:type:: Broker::Type
   :source-code: base/frameworks/broker/log.zeek 13 19

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::STATUS Broker::Type

         An informational status update.

      .. zeek:enum:: Broker::ERROR Broker::Type

         An error situation.

   The type of a Broker activity being logged.

Hooks
#####
.. zeek:id:: Broker::log_policy
   :source-code: base/frameworks/broker/log.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


