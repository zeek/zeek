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
=============================================== =
:zeek:type:`IGMP::IgmpLog`: :zeek:type:`record` 
=============================================== =

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


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: IGMP::IgmpLog
   :source-code: base/packet-protocols/igmp/main.zeek 12 17

   :Type: :zeek:type:`record`


   .. zeek:field:: timestamp :zeek:type:`time` :zeek:attr:`&log`


   .. zeek:field:: src_addr :zeek:type:`addr` :zeek:attr:`&log`


   .. zeek:field:: dst_addr :zeek:type:`addr` :zeek:attr:`&log`


   .. zeek:field:: msg_type :zeek:type:`IGMP::IgmpMessageType` :zeek:attr:`&log`



Events
######
.. zeek:id:: IGMP::log_igmp
   :source-code: base/packet-protocols/igmp/main.zeek 21 21

   :Type: :zeek:type:`event` (rec: :zeek:type:`IGMP::IgmpLog`)

   Event that can be handled to access the IGMP record as it is sent on
   to the logging framework.


