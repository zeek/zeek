:tocdepth: 3

base/protocols/snmp/main.zeek
=============================
.. zeek:namespace:: SNMP

Enables analysis and logging of SNMP datagrams.

:Namespace: SNMP
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================================== ========================================================
:zeek:id:`SNMP::ports`: :zeek:type:`set` :zeek:attr:`&redef`                                               Well-known ports for SNMP.
:zeek:id:`SNMP::version_map`: :zeek:type:`table` :zeek:attr:`&redef` :zeek:attr:`&default` = ``"unknown"`` Maps an SNMP version integer to a human readable string.
========================================================================================================== ========================================================

Types
#####
============================================ =====================================
:zeek:type:`SNMP::Info`: :zeek:type:`record` Information tracked per SNMP session.
============================================ =====================================

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`SNMP::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               snmp: :zeek:type:`SNMP::Info` :zeek:attr:`&optional`
============================================ ======================================================

Events
######
============================================= ====================================================================
:zeek:id:`SNMP::log_snmp`: :zeek:type:`event` Event that can be handled to access the SNMP record as it is sent on
                                              to the logging framework.
============================================= ====================================================================

Hooks
#####
============================================================== =======================
:zeek:id:`SNMP::finalize_snmp`: :zeek:type:`Conn::RemovalHook` SNMP finalization hook.
:zeek:id:`SNMP::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SNMP::ports
   :source-code: base/protocols/snmp/main.zeek 11 11

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            162/udp,
            161/udp
         }


   Well-known ports for SNMP.

.. zeek:id:: SNMP::version_map
   :source-code: base/protocols/snmp/main.zeek 57 57

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&default` = ``"unknown"``
   :Default:

      ::

         {
            [0] = "1",
            [1] = "2c",
            [3] = "3"
         }


   Maps an SNMP version integer to a human readable string.

Types
#####
.. zeek:type:: SNMP::Info
   :source-code: base/protocols/snmp/main.zeek 16 54

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of first packet belonging to the SNMP session.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      The unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 5-tuple of addresses/ports (ports inherently
      include transport protocol information)


   .. zeek:field:: duration :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

      The amount of time between the first packet belonging to
      the SNMP session and the latest one seen.


   .. zeek:field:: version :zeek:type:`string` :zeek:attr:`&log`

      The version of SNMP being used.


   .. zeek:field:: community :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      v1/v2c: The community string (v1/v2c) of the first SNMP
      packet associated with the session. This is used as part of SNMP's (v1 and v2c)
      administrative/security framework.
      v3: The username of the first SNMP packet containing a non-zero username.
      See :rfc:`1157` (SNMP v1), :rfc:`1901` (SNMP v2), or :rfc:`2570` (SNMP v3).


   .. zeek:field:: get_requests :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of variable bindings in GetRequest/GetNextRequest PDUs
      seen for the session.


   .. zeek:field:: get_bulk_requests :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of variable bindings in GetBulkRequest PDUs seen for
      the session.


   .. zeek:field:: get_responses :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of variable bindings in GetResponse/Response PDUs seen
      for the session.


   .. zeek:field:: set_requests :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of variable bindings in SetRequest PDUs seen for
      the session.


   .. zeek:field:: display_string :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A system description of the SNMP responder endpoint.


   .. zeek:field:: up_since :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      The time at which the SNMP responder endpoint claims it's been
      up since.


   Information tracked per SNMP session.

Events
######
.. zeek:id:: SNMP::log_snmp
   :source-code: base/protocols/snmp/main.zeek 65 65

   :Type: :zeek:type:`event` (rec: :zeek:type:`SNMP::Info`)

   Event that can be handled to access the SNMP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: SNMP::finalize_snmp
   :source-code: base/protocols/snmp/main.zeek 107 111

   :Type: :zeek:type:`Conn::RemovalHook`

   SNMP finalization hook.  Remaining SNMP info may get logged when it's called.

.. zeek:id:: SNMP::log_policy
   :source-code: base/protocols/snmp/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



