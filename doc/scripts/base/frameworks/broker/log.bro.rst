:tocdepth: 3

base/frameworks/broker/log.bro
==============================
.. bro:namespace:: Broker


:Namespace: Broker
:Imports: :doc:`base/frameworks/broker/main.bro </scripts/base/frameworks/broker/main.bro>`

Summary
~~~~~~~
Types
#####
============================================ =============================================================
:bro:type:`Broker::Info`: :bro:type:`record` A record type containing the column fields of the Broker log.
:bro:type:`Broker::Type`: :bro:type:`enum`   The type of a Broker activity being logged.
============================================ =============================================================

Redefinitions
#############
===================================== =====================================
:bro:type:`Log::ID`: :bro:type:`enum` The Broker logging stream identifier.
===================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Broker::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The network time at which a Broker event occurred.

      ty: :bro:type:`Broker::Type` :bro:attr:`&log`
         The type of the Broker event.

      ev: :bro:type:`string` :bro:attr:`&log`
         The event being logged.

      peer: :bro:type:`Broker::NetworkInfo` :bro:attr:`&log` :bro:attr:`&optional`
         The peer (if any) with which a Broker event is
         concerned.

      message: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         An optional message describing the Broker event in more detail

   A record type containing the column fields of the Broker log.

.. bro:type:: Broker::Type

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::STATUS Broker::Type

         An informational status update.

      .. bro:enum:: Broker::ERROR Broker::Type

         An error situation.

   The type of a Broker activity being logged.


