:tocdepth: 3

base/packet-protocols/igmp/main.zeek
====================================
.. zeek:namespace:: IGMP

Implements base functionality for IGMP analysis.

:Namespace: IGMP
:Imports: :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== =====================================================================
:zeek:id:`IGMP::rate_limit_duration`: :zeek:type:`interval` :zeek:attr:`&redef` The amount of time for which repeat messages remain suppressed once
                                                                                rate-limiting applies.
:zeek:id:`IGMP::rate_limit_repeats`: :zeek:type:`count` :zeek:attr:`&redef`     The number of repeats of the same action that are allowed before Zeek
                                                                                suppresses such messages.
=============================================================================== =====================================================================

Types
#####
================================================= =====================================================================
:zeek:type:`IGMP::GroupAction`: :zeek:type:`enum` A generic enum to map the v1/v2/v3 state changes to something common.
:zeek:type:`IGMP::Info`: :zeek:type:`record`      The record type which contains the column fields of the IGMP log.
================================================= =====================================================================

Redefinitions
#############
======================================= ========================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                        * :zeek:enum:`IGMP::LOG`
======================================= ========================

Events
######
============================================= ====================================================================
:zeek:id:`IGMP::log_igmp`: :zeek:type:`event` Event that can be handled to access the IGMP record as it is sent on
                                              to the logging framework.
============================================= ====================================================================

Hooks
#####
========================================================= =============================================
:zeek:id:`IGMP::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
========================================================= =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: IGMP::rate_limit_duration
   :source-code: base/packet-protocols/igmp/main.zeek 42 42

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   The amount of time for which repeat messages remain suppressed once
   rate-limiting applies.

.. zeek:id:: IGMP::rate_limit_repeats
   :source-code: base/packet-protocols/igmp/main.zeek 38 38

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   The number of repeats of the same action that are allowed before Zeek
   suppresses such messages.

Types
#####
.. zeek:type:: IGMP::GroupAction
   :source-code: base/packet-protocols/igmp/main.zeek 14 18

   :Type: :zeek:type:`enum`

      .. zeek:enum:: IGMP::JOIN IGMP::GroupAction

      .. zeek:enum:: IGMP::LEAVE IGMP::GroupAction

   A generic enum to map the v1/v2/v3 state changes to something common.

.. zeek:type:: IGMP::Info
   :source-code: base/packet-protocols/igmp/main.zeek 20 30

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The network time when the message was received.


   .. zeek:field:: src :zeek:type:`addr` :zeek:attr:`&log`

      Source IP address of the message.


   .. zeek:field:: group :zeek:type:`addr` :zeek:attr:`&log`

      Destination group address, as per the
      `IANA Multicast Address Registry <https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml>`_


   .. zeek:field:: action :zeek:type:`IGMP::GroupAction` :zeek:attr:`&log`

      IGMP action requested in the message.


   The record type which contains the column fields of the IGMP log.

Events
######
.. zeek:id:: IGMP::log_igmp
   :source-code: base/packet-protocols/igmp/main.zeek 34 34

   :Type: :zeek:type:`event` (rec: :zeek:type:`IGMP::Info`)

   Event that can be handled to access the IGMP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: IGMP::log_policy
   :source-code: base/packet-protocols/igmp/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


