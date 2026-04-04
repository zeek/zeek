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
   :source-code: base/frameworks/broker/log.zeek 33 45

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The network time at which a Broker event occurred.


   .. zeek:field:: ty :zeek:type:`Broker::Type` :zeek:attr:`&log`

      The type of the Broker event.


   .. zeek:field:: ev :zeek:type:`string` :zeek:attr:`&log`

      The event being logged.


   .. zeek:field:: peer :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&log` :zeek:attr:`&optional`

      The peer (if any) with which a Broker event is
      concerned.


   .. zeek:field:: message :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      An optional message describing the Broker event in more detail


   A record type containing the column fields of the Broker log.

.. zeek:type:: Broker::Type
   :source-code: base/frameworks/broker/log.zeek 13 31

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::STATUS Broker::Type

         An informational status update.

      .. zeek:enum:: Broker::ERROR Broker::Type

         An error situation.

      .. zeek:enum:: Broker::CRITICAL_EVENT Broker::Type

         Fatal event, normal operation has most likely broken down.

      .. zeek:enum:: Broker::ERROR_EVENT Broker::Type

         Unrecoverable event that imparts at least part of the system.

      .. zeek:enum:: Broker::WARNING_EVENT Broker::Type

         Unexpected or conspicuous event that may still be recoverable.

      .. zeek:enum:: Broker::INFO_EVENT Broker::Type

         Noteworthy event during normal operation.

      .. zeek:enum:: Broker::VERBOSE_EVENT Broker::Type

         Information that might be relevant for a user to understand system behavior.

      .. zeek:enum:: Broker::DEBUG_EVENT Broker::Type

         An event that is relevant only for troubleshooting and debugging.

   The type of a Broker activity being logged.

Hooks
#####
.. zeek:id:: Broker::log_policy
   :source-code: base/frameworks/broker/log.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


