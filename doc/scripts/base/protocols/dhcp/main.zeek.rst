:tocdepth: 3

base/protocols/dhcp/main.zeek
=============================
.. zeek:namespace:: DHCP

Analyze DHCP traffic and provide a log that is organized around
the idea of a DHCP "conversation" defined by messages exchanged within
a relatively short period of time using the same transaction ID.
The log will have information from clients and servers to give a more
complete picture of what happened.

:Namespace: DHCP
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/dhcp/consts.zeek </scripts/base/protocols/dhcp/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================== ================================================================
:zeek:id:`DHCP::max_msg_types_per_log_entry`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of msg_types allowed in a single log entry.
:zeek:id:`DHCP::max_txid_watch_time`: :zeek:type:`interval` :zeek:attr:`&redef`      The maximum amount of time that a transaction ID will be watched
                                                                                     for to try and tie messages together into a single DHCP
                                                                                     transaction narrative.
:zeek:id:`DHCP::max_uids_per_log_entry`: :zeek:type:`count` :zeek:attr:`&redef`      The maximum number of uids allowed in a single log entry.
==================================================================================== ================================================================

State Variables
###############
================================================== ========================================================
:zeek:id:`DHCP::log_info`: :zeek:type:`DHCP::Info` This is a global variable that is only to be used in the
                                                   :zeek:see:`DHCP::aggregate_msgs` event.
================================================== ========================================================

Types
#####
============================================ =================================================================
:zeek:type:`DHCP::Info`: :zeek:type:`record` The record type which contains the column fields of the DHCP log.
============================================ =================================================================

Redefinitions
#############
==================================================================== ===========================================================
:zeek:type:`DHCP::Info`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`DHCP::Info`
                                                                     
                                                                       last_message_ts: :zeek:type:`time` :zeek:attr:`&optional`
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`DHCP::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       dhcp: :zeek:type:`DHCP::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ===========================================================

Events
######
=================================================== ================================================================
:zeek:id:`DHCP::aggregate_msgs`: :zeek:type:`event` This event is used internally to distribute data around clusters
                                                    since DHCP doesn't follow the normal "connection" model used by
                                                    most protocols.
:zeek:id:`DHCP::log_dhcp`: :zeek:type:`event`       Event that can be handled to access the DHCP
                                                    record as it is sent on to the logging framework.
=================================================== ================================================================

Hooks
#####
========================================================= =
:zeek:id:`DHCP::log_policy`: :zeek:type:`Log::PolicyHook` 
========================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DHCP::max_msg_types_per_log_entry
   :source-code: base/protocols/dhcp/main.zeek 98 98

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50``

   The maximum number of msg_types allowed in a single log entry.

.. zeek:id:: DHCP::max_txid_watch_time
   :source-code: base/protocols/dhcp/main.zeek 92 92

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``

   The maximum amount of time that a transaction ID will be watched
   for to try and tie messages together into a single DHCP
   transaction narrative.

.. zeek:id:: DHCP::max_uids_per_log_entry
   :source-code: base/protocols/dhcp/main.zeek 95 95

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   The maximum number of uids allowed in a single log entry.

State Variables
###############
.. zeek:id:: DHCP::log_info
   :source-code: base/protocols/dhcp/main.zeek 110 110

   :Type: :zeek:type:`DHCP::Info`
   :Default:

      ::

         {
            ts=<uninitialized>
            uids={

            }
            client_addr=<uninitialized>
            server_addr=<uninitialized>
            client_port=<uninitialized>
            server_port=<uninitialized>
            mac=<uninitialized>
            host_name=<uninitialized>
            client_fqdn=<uninitialized>
            domain=<uninitialized>
            requested_addr=<uninitialized>
            assigned_addr=<uninitialized>
            lease_time=<uninitialized>
            client_message=<uninitialized>
            server_message=<uninitialized>
            msg_types=[]
            duration=0 secs
            client_chaddr=<uninitialized>
            last_message_ts=<uninitialized>
            msg_orig=[]
            client_software=<uninitialized>
            server_software=<uninitialized>
            circuit_id=<uninitialized>
            agent_remote_id=<uninitialized>
            subscriber_id=<uninitialized>
         }


   This is a global variable that is only to be used in the
   :zeek:see:`DHCP::aggregate_msgs` event. It can be used to avoid
   looking up the info record for a transaction ID in every event handler
   for :zeek:see:`DHCP::aggregate_msgs`.

Types
#####
.. zeek:type:: DHCP::Info
   :source-code: base/protocols/dhcp/main.zeek 18 87

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The earliest time at which a DHCP message over the
         associated connection is observed.

      uids: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log`
         A series of unique identifiers of the connections over which
         DHCP is occurring.  This behavior with multiple connections is
         unique to DHCP because of the way it uses broadcast packets
         on local networks.

      client_addr: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IP address of the client.  If a transaction
         is only a client sending INFORM messages then
         there is no lease information exchanged so this
         is helpful to know who sent the messages.
         Getting an address in this field does require
         that the client sources at least one DHCP message
         using a non-broadcast address.

      server_addr: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IP address of the server involved in actually
         handing out the lease.  There could be other
         servers replying with OFFER messages which won't
         be represented here.  Getting an address in this
         field also requires that the server handing out
         the lease also sources packets from a non-broadcast
         IP address.

      client_port: :zeek:type:`port` :zeek:attr:`&optional`
         Client port number seen at time of server handing out IP (expected
         as 68/udp).

      server_port: :zeek:type:`port` :zeek:attr:`&optional`
         Server port number seen at time of server handing out IP (expected
         as 67/udp).

      mac: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Client's hardware address.

      host_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Name given by client in Hostname option 12.

      client_fqdn: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         FQDN given by client in Client FQDN option 81.

      domain: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Domain given by the server in option 15.

      requested_addr: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IP address requested by the client.

      assigned_addr: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IP address assigned by the server.

      lease_time: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`
         IP address lease interval.

      client_message: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Message typically accompanied with a DHCP_DECLINE
         so the client can tell the server why it rejected
         an address.

      server_message: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Message typically accompanied with a DHCP_NAK to let
         the client know why it rejected the request.

      msg_types: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         The DHCP message types seen by this DHCP transaction

      duration: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`
         Duration of the DHCP "session" representing the
         time from the first message to the last.

      client_chaddr: :zeek:type:`string` :zeek:attr:`&optional`
         The CHADDR field sent by the client.

      last_message_ts: :zeek:type:`time` :zeek:attr:`&optional`

      msg_orig: :zeek:type:`vector` of :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/msg-orig.zeek` is loaded)

         The address that originated each message from the
         `msg_types` field.

      client_software: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)

         Software reported by the client in the `vendor_class` option.

      server_software: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)

         Software reported by the server in the `vendor_class` option.

      circuit_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         Added by DHCP relay agents which terminate switched or
         permanent circuits.  It encodes an agent-local identifier
         of the circuit from which a DHCP client-to-server packet was
         received.  Typically it should represent a router or switch
         interface number.

      agent_remote_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         A globally unique identifier added by relay agents to identify
         the remote host end of the circuit.

      subscriber_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         The subscriber ID is a value independent of the physical
         network configuration so that a customer's DHCP configuration
         can be given to them correctly no matter where they are
         physically connected.

   The record type which contains the column fields of the DHCP log.

Events
######
.. zeek:id:: DHCP::aggregate_msgs
   :source-code: base/protocols/dhcp/main.zeek 104 104

   :Type: :zeek:type:`event` (ts: :zeek:type:`time`, id: :zeek:type:`conn_id`, uid: :zeek:type:`string`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`DHCP::Msg`, options: :zeek:type:`DHCP::Options`)

   This event is used internally to distribute data around clusters
   since DHCP doesn't follow the normal "connection" model used by
   most protocols. It can also be handled to extend the DHCP log.
   :zeek:see:`DHCP::log_info`.

.. zeek:id:: DHCP::log_dhcp
   :source-code: policy/protocols/dhcp/software.zeek 40 64

   :Type: :zeek:type:`event` (rec: :zeek:type:`DHCP::Info`)

   Event that can be handled to access the DHCP
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: DHCP::log_policy
   :source-code: base/protocols/dhcp/main.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`



