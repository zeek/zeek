:tocdepth: 3

base/packet-protocols/igmp/main.zeek
====================================
.. zeek:namespace:: IGMP

Implements base functionality for IGMP analysis.
Registers the IGMP packet analyzer.
Generates the IGMP.log file.

:Namespace: IGMP
:Imports: :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Types
#####
============================================ =================================================================
:zeek:type:`IGMP::Info`: :zeek:type:`record` The record type which contains the column fields of the IGMP log.
============================================ =================================================================

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
Types
#####
.. zeek:type:: IGMP::Info
   :source-code: base/packet-protocols/igmp/main.zeek 16 25

   :Type: :zeek:type:`record`


   .. zeek:field:: timestamp :zeek:type:`time` :zeek:attr:`&log`

      Timestamp


   .. zeek:field:: src_addr :zeek:type:`addr` :zeek:attr:`&log`

      Source IP address


   .. zeek:field:: dst_addr :zeek:type:`addr` :zeek:attr:`&log`

      Destination IP address


   .. zeek:field:: msg_type :zeek:type:`IGMP::MessageType` :zeek:attr:`&log`

      Message type


   The record type which contains the column fields of the IGMP log.

Events
######
.. zeek:id:: IGMP::log_igmp
   :source-code: base/packet-protocols/igmp/main.zeek 29 29

   :Type: :zeek:type:`event` (rec: :zeek:type:`IGMP::Info`)

   Event that can be handled to access the IGMP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: IGMP::log_policy
   :source-code: base/packet-protocols/igmp/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


