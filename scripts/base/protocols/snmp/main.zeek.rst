:tocdepth: 3

base/protocols/snmp/main.zeek
=============================
.. bro:namespace:: SNMP

Enables analysis and logging of SNMP datagrams.

:Namespace: SNMP

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================================================ ========================================================
:bro:id:`SNMP::version_map`: :bro:type:`table` :bro:attr:`&redef` :bro:attr:`&default` = ``"unknown"`` :bro:attr:`&optional` Maps an SNMP version integer to a human readable string.
============================================================================================================================ ========================================================

Types
#####
========================================== =====================================
:bro:type:`SNMP::Info`: :bro:type:`record` Information tracked per SNMP session.
========================================== =====================================

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=========================================== ====================================================================
:bro:id:`SNMP::log_snmp`: :bro:type:`event` Event that can be handled to access the SNMP record as it is sent on
                                            to the logging framework.
=========================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: SNMP::version_map

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&redef` :bro:attr:`&default` = ``"unknown"`` :bro:attr:`&optional`
   :Default:

   ::

      {
         [1] = "2c",
         [0] = "1",
         [3] = "3"
      }

   Maps an SNMP version integer to a human readable string.

Types
#####
.. bro:type:: SNMP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp of first packet belonging to the SNMP session.

      uid: :bro:type:`string` :bro:attr:`&log`
         The unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 5-tuple of addresses/ports (ports inherently
         include transport protocol information)

      duration: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`
         The amount of time between the first packet beloning to
         the SNMP session and the latest one seen.

      version: :bro:type:`string` :bro:attr:`&log`
         The version of SNMP being used.

      community: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The community string of the first SNMP packet associated with
         the session.  This is used as part of SNMP's (v1 and v2c)
         administrative/security framework.  See :rfc:`1157` or :rfc:`1901`.

      get_requests: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of variable bindings in GetRequest/GetNextRequest PDUs
         seen for the session.

      get_bulk_requests: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of variable bindings in GetBulkRequest PDUs seen for
         the session.

      get_responses: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of variable bindings in GetResponse/Response PDUs seen
         for the session.

      set_requests: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of variable bindings in SetRequest PDUs seen for
         the session.

      display_string: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A system description of the SNMP responder endpoint.

      up_since: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The time at which the SNMP responder endpoint claims it's been
         up since.

   Information tracked per SNMP session.

Events
######
.. bro:id:: SNMP::log_snmp

   :Type: :bro:type:`event` (rec: :bro:type:`SNMP::Info`)

   Event that can be handled to access the SNMP record as it is sent on
   to the logging framework.


