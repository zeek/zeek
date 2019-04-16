:tocdepth: 3

base/protocols/dhcp/main.zeek
=============================
.. bro:namespace:: DHCP

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
============================================================================ ===============================================================
:bro:id:`DHCP::max_txid_watch_time`: :bro:type:`interval` :bro:attr:`&redef` The maximum amount of time that a transation ID will be watched
                                                                             for to try and tie messages together into a single DHCP
                                                                             transaction narrative.
============================================================================ ===============================================================

State Variables
###############
================================================ ========================================================
:bro:id:`DHCP::log_info`: :bro:type:`DHCP::Info` This is a global variable that is only to be used in the
                                                 :bro::see::`DHCP::aggregate_msgs` event.
================================================ ========================================================

Types
#####
========================================== =================================================================
:bro:type:`DHCP::Info`: :bro:type:`record` The record type which contains the column fields of the DHCP log.
========================================== =================================================================

Redefinitions
#############
================================================================= =
:bro:type:`DHCP::Info`: :bro:type:`record`                        
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
================================================= ================================================================
:bro:id:`DHCP::aggregate_msgs`: :bro:type:`event` This event is used internally to distribute data around clusters
                                                  since DHCP doesn't follow the normal "connection" model used by
                                                  most protocols.
:bro:id:`DHCP::log_dhcp`: :bro:type:`event`       Event that can be handled to access the DHCP
                                                  record as it is sent on to the logging framework.
================================================= ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DHCP::max_txid_watch_time

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 secs``

   The maximum amount of time that a transation ID will be watched
   for to try and tie messages together into a single DHCP
   transaction narrative.

State Variables
###############
.. bro:id:: DHCP::log_info

   :Type: :bro:type:`DHCP::Info`
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
         last_message_ts=<uninitialized>
         msg_orig=<uninitialized>
         client_software=<uninitialized>
         server_software=<uninitialized>
         circuit_id=<uninitialized>
         agent_remote_id=<uninitialized>
         subscriber_id=<uninitialized>
      }

   This is a global variable that is only to be used in the
   :bro::see::`DHCP::aggregate_msgs` event. It can be used to avoid
   looking up the info record for a transaction ID in every event handler
   for :bro:see::`DHCP::aggregate_msgs`.

Types
#####
.. bro:type:: DHCP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The earliest time at which a DHCP message over the
         associated connection is observed.

      uids: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log`
         A series of unique identifiers of the connections over which
         DHCP is occurring.  This behavior with multiple connections is
         unique to DHCP because of the way it uses broadcast packets
         on local networks.

      client_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IP address of the client.  If a transaction
         is only a client sending INFORM messages then
         there is no lease information exchanged so this
         is helpful to know who sent the messages.
         Getting an address in this field does require
         that the client sources at least one DHCP message
         using a non-broadcast address.

      server_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IP address of the server involved in actually
         handing out the lease.  There could be other
         servers replying with OFFER messages which won't
         be represented here.  Getting an address in this
         field also requires that the server handing out
         the lease also sources packets from a non-broadcast
         IP address.

      client_port: :bro:type:`port` :bro:attr:`&optional`
         Client port number seen at time of server handing out IP (expected
         as 68/udp).

      server_port: :bro:type:`port` :bro:attr:`&optional`
         Server port number seen at time of server handing out IP (expected
         as 67/udp).

      mac: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Client's hardware address.

      host_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Name given by client in Hostname option 12.

      client_fqdn: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         FQDN given by client in Client FQDN option 81.

      domain: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Domain given by the server in option 15.

      requested_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IP address requested by the client.

      assigned_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IP address assigned by the server.

      lease_time: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         IP address lease interval.

      client_message: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Message typically accompanied with a DHCP_DECLINE
         so the client can tell the server why it rejected
         an address.

      server_message: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Message typically accompanied with a DHCP_NAK to let
         the client know why it rejected the request.

      msg_types: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         The DHCP message types seen by this DHCP transaction

      duration: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`
         Duration of the DHCP "session" representing the 
         time from the first message to the last.

      last_message_ts: :bro:type:`time` :bro:attr:`&optional`

      msg_orig: :bro:type:`vector` of :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/msg-orig.zeek` is loaded)

         The address that originated each message from the
         `msg_types` field.

      client_software: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)

         Software reported by the client in the `vendor_class` option.

      server_software: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)

         Software reported by the server in the `vendor_class` option.

      circuit_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         Added by DHCP relay agents which terminate switched or
         permanent circuits.  It encodes an agent-local identifier
         of the circuit from which a DHCP client-to-server packet was
         received.  Typically it should represent a router or switch
         interface number.

      agent_remote_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         A globally unique identifier added by relay agents to identify
         the remote host end of the circuit.

      subscriber_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dhcp/sub-opts.zeek` is loaded)

         The subscriber ID is a value independent of the physical
         network configuration so that a customer's DHCP configuration
         can be given to them correctly no matter where they are
         physically connected.

   The record type which contains the column fields of the DHCP log.

Events
######
.. bro:id:: DHCP::aggregate_msgs

   :Type: :bro:type:`event` (ts: :bro:type:`time`, id: :bro:type:`conn_id`, uid: :bro:type:`string`, is_orig: :bro:type:`bool`, msg: :bro:type:`DHCP::Msg`, options: :bro:type:`DHCP::Options`)

   This event is used internally to distribute data around clusters
   since DHCP doesn't follow the normal "connection" model used by
   most protocols. It can also be handled to extend the DHCP log.

   :bro:see::`DHCP::log_info`.

.. bro:id:: DHCP::log_dhcp

   :Type: :bro:type:`event` (rec: :bro:type:`DHCP::Info`)

   Event that can be handled to access the DHCP
   record as it is sent on to the logging framework.


