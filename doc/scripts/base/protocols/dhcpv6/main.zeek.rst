:tocdepth: 3

base/protocols/dhcpv6/main.zeek
===============================
.. zeek:namespace:: DHCPv6

Analyze DHCPv6 (:rfc:`8415`) traffic and produce a ``dhcpv6.log`` organized
around a DHCPv6 "transaction": the messages exchanged between clients and
servers that share a transaction identifier. Because DHCPv6 uses multicast
and separate client/server flows, a single transaction involves multiple
UDP messages

:Namespace: DHCPv6
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/dhcpv6/consts.zeek </scripts/base/protocols/dhcpv6/consts.zeek>`, :doc:`base/protocols/dhcpv6/spicy-events.zeek </scripts/base/protocols/dhcpv6/spicy-events.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================= ==============================================================
:zeek:id:`DHCPv6::transaction_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The maximum amount of time a transaction is tracked before its
                                                                                  aggregated record is written to the log.
================================================================================= ==============================================================

Redefinable Options
###################
============================================================================= ====================================================================
:zeek:id:`DHCPv6::client_ports`: :zeek:type:`set` :zeek:attr:`&redef`
:zeek:id:`DHCPv6::server_message_types`: :zeek:type:`set` :zeek:attr:`&redef` Message types that originate from a DHCPv6 server.
:zeek:id:`DHCPv6::server_ports`: :zeek:type:`set` :zeek:attr:`&redef`         Well-known DHCPv6 server ports (547/udp) and client ports (546/udp).
============================================================================= ====================================================================

Types
#####
============================================== ===================================================================
:zeek:type:`DHCPv6::Info`: :zeek:type:`record` The record type which contains the column fields of the DHCPv6 log.
============================================== ===================================================================

Redefinitions
#############
======================================= ==========================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                        * :zeek:enum:`DHCPv6::LOG`
======================================= ==========================

Events
######
===================================================== =====================================================================
:zeek:id:`DHCPv6::aggregate_msgs`: :zeek:type:`event` This event is used internally to distribute messages to the manager
                                                      for aggregation, since DHCPv6 does not follow the normal "connection"
                                                      model used by most protocols.
:zeek:id:`DHCPv6::log_dhcpv6`: :zeek:type:`event`     Event that can be handled to access the DHCPv6 record as it is sent
                                                      on to the logging framework.
===================================================== =====================================================================

Hooks
#####
=========================================================== =
:zeek:id:`DHCPv6::log_policy`: :zeek:type:`Log::PolicyHook`
=========================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DHCPv6::transaction_timeout
   :source-code: base/protocols/dhcpv6/main.zeek 81 81

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``

   The maximum amount of time a transaction is tracked before its
   aggregated record is written to the log.

Redefinable Options
###################
.. zeek:id:: DHCPv6::client_ports
   :source-code: base/protocols/dhcpv6/main.zeek 18 18

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            546/udp
         }



.. zeek:id:: DHCPv6::server_message_types
   :source-code: base/protocols/dhcpv6/main.zeek 73 73

   :Type: :zeek:type:`set` [:zeek:type:`count`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            2,
            7,
            10
         }


   Message types that originate from a DHCPv6 server. All others are
   treated as client messages. See :rfc:`8415#section-7.3`.

.. zeek:id:: DHCPv6::server_ports
   :source-code: base/protocols/dhcpv6/main.zeek 17 17

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            547/udp
         }


   Well-known DHCPv6 server ports (547/udp) and client ports (546/udp).

Types
#####
.. zeek:type:: DHCPv6::Info
   :source-code: base/protocols/dhcpv6/main.zeek 23 69

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The earliest time at which a message in this transaction was
      observed.


   .. zeek:field:: transaction_id :zeek:type:`count` :zeek:attr:`&log`

      The transaction identifier tying the exchange together.


   .. zeek:field:: uids :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log`

      Unique identifiers of the connections over which this
      transaction was observed.


   .. zeek:field:: client_msg_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The most recent message type sent by a client.


   .. zeek:field:: server_msg_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The most recent message type sent by a server.


   .. zeek:field:: msg_types :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      All message types observed in this transaction, in order.


   .. zeek:field:: client_duid_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The type of the client DUID (e.g., ``LLT``, ``LL``, ``EN``, ``UUID``).


   .. zeek:field:: client_duid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The client DUID as a hex string.


   .. zeek:field:: server_duid_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The type of the server DUID (e.g., ``LLT``, ``LL``, ``EN``, ``UUID``).


   .. zeek:field:: server_duid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The server DUID as a hex string.


   .. zeek:field:: requested_options :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Option names requested by the client (option ORO).


   .. zeek:field:: iaid :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The IAID of the first IA_NA option seen.


   .. zeek:field:: assigned_addr :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`

      The address assigned by the server (first IA Address option).


   .. zeek:field:: preferred_lifetime :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      Preferred lifetime of the assigned address.


   .. zeek:field:: valid_lifetime :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      Valid lifetime of the assigned address.


   .. zeek:field:: status :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status code name returned by the server (option STATUS_CODE).


   .. zeek:field:: status_message :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status message returned by the server (option STATUS_CODE).


   .. zeek:field:: client_fqdn :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      FQDN provided by the client (option CLIENT_FQDN).


   .. zeek:field:: duration :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

      Duration from the first to the last message of the transaction.


   The record type which contains the column fields of the DHCPv6 log.

Events
######
.. zeek:id:: DHCPv6::aggregate_msgs
   :source-code: base/protocols/dhcpv6/main.zeek 114 172

   :Type: :zeek:type:`event` (ts: :zeek:type:`time`, uid: :zeek:type:`string`, msg: :zeek:type:`DHCPv6::MessageInfo`)

   This event is used internally to distribute messages to the manager
   for aggregation, since DHCPv6 does not follow the normal "connection"
   model used by most protocols. It can also be handled to extend the
   DHCPv6 log.

.. zeek:id:: DHCPv6::log_dhcpv6
   :source-code: base/protocols/dhcpv6/main.zeek 91 91

   :Type: :zeek:type:`event` (rec: :zeek:type:`DHCPv6::Info`)

   Event that can be handled to access the DHCPv6 record as it is sent
   on to the logging framework.

Hooks
#####
.. zeek:id:: DHCPv6::log_policy
   :source-code: base/protocols/dhcpv6/main.zeek 20 20

   :Type: :zeek:type:`Log::PolicyHook`



