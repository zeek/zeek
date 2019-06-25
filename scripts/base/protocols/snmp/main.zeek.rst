:tocdepth: 3

base/protocols/snmp/main.zeek
=============================
.. zeek:namespace:: SNMP

Enables analysis and logging of SNMP datagrams.

:Namespace: SNMP

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================================= ========================================================
:zeek:id:`SNMP::version_map`: :zeek:type:`table` :zeek:attr:`&redef` :zeek:attr:`&default` = ``"unknown"`` :zeek:attr:`&optional` Maps an SNMP version integer to a human readable string.
================================================================================================================================= ========================================================

Types
#####
============================================ =====================================
:zeek:type:`SNMP::Info`: :zeek:type:`record` Information tracked per SNMP session.
============================================ =====================================

Redefinitions
#############
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
============================================= ====================================================================
:zeek:id:`SNMP::log_snmp`: :zeek:type:`event` Event that can be handled to access the SNMP record as it is sent on
                                              to the logging framework.
============================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SNMP::version_map

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&default` = ``"unknown"`` :zeek:attr:`&optional`
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
.. zeek:type:: SNMP::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of first packet belonging to the SNMP session.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         The unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 5-tuple of addresses/ports (ports inherently
         include transport protocol information)

      duration: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`
         The amount of time between the first packet beloning to
         the SNMP session and the latest one seen.

      version: :zeek:type:`string` :zeek:attr:`&log`
         The version of SNMP being used.

      community: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The community string of the first SNMP packet associated with
         the session.  This is used as part of SNMP's (v1 and v2c)
         administrative/security framework.  See :rfc:`1157` or :rfc:`1901`.

      get_requests: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of variable bindings in GetRequest/GetNextRequest PDUs
         seen for the session.

      get_bulk_requests: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of variable bindings in GetBulkRequest PDUs seen for
         the session.

      get_responses: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of variable bindings in GetResponse/Response PDUs seen
         for the session.

      set_requests: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of variable bindings in SetRequest PDUs seen for
         the session.

      display_string: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         A system description of the SNMP responder endpoint.

      up_since: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         The time at which the SNMP responder endpoint claims it's been
         up since.

   Information tracked per SNMP session.

Events
######
.. zeek:id:: SNMP::log_snmp

   :Type: :zeek:type:`event` (rec: :zeek:type:`SNMP::Info`)

   Event that can be handled to access the SNMP record as it is sent on
   to the logging framework.


