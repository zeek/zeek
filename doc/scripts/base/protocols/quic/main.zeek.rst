:tocdepth: 3

base/protocols/quic/main.zeek
=============================
.. zeek:namespace:: QUIC

Initial idea for a quic.log.

:Namespace: QUIC
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/quic/consts.zeek </scripts/base/protocols/quic/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ========================================
:zeek:id:`QUIC::max_history_length`: :zeek:type:`count` :zeek:attr:`&redef` The maximum length of the history field.
=========================================================================== ========================================

Types
#####
============================================ =
:zeek:type:`QUIC::Info`: :zeek:type:`record` 
============================================ =

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`QUIC::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               quic: :zeek:type:`QUIC::Info` :zeek:attr:`&optional`
============================================ ======================================================

Events
######
============================================= =
:zeek:id:`QUIC::log_quic`: :zeek:type:`event` 
============================================= =

Hooks
#####
============================================================== =
:zeek:id:`QUIC::finalize_quic`: :zeek:type:`Conn::RemovalHook` 
:zeek:id:`QUIC::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: QUIC::max_history_length
   :source-code: base/protocols/quic/main.zeek 77 77

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum length of the history field.

Types
#####
.. zeek:type:: QUIC::Info
   :source-code: base/protocols/quic/main.zeek 13 68

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of first QUIC packet for this entry.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`string` :zeek:attr:`&log`
         QUIC version as found in the first INITIAL packet from
         the client.

      client_initial_dcid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         First Destination Connection ID used by client. This is
         random and unpredictable, but used for packet protection
         by client and server.

      client_scid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Client's Source Connection ID from the first INITIAL packet.

      server_scid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server chosen Connection ID usually from server's first
         INITIAL packet. This is to be used by the client in
         subsequent packets.

      server_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server name extracted from SNI extension in ClientHello
         packet if available.

      client_protocol: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         First protocol extracted from ALPN extension in ClientHello
         packet if available.

      history: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Experimental QUIC history.
         
         Letters have the following meaning with client-sent
         letters being capitalized:
         
         ======  ====================================================
         Letter  Meaning
         ======  ====================================================
         I       INIT packet
         H       HANDSHAKE packet
         Z       0RTT packet
         R       RETRY packet
         C       CONNECTION_CLOSE packet
         S       SSL Client/Server Hello
         ======  ====================================================

      history_state: :zeek:type:`vector` of :zeek:type:`string`

      logged: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`


Events
######
.. zeek:id:: QUIC::log_quic
   :source-code: base/protocols/quic/main.zeek 70 70

   :Type: :zeek:type:`event` (rec: :zeek:type:`QUIC::Info`)


Hooks
#####
.. zeek:id:: QUIC::finalize_quic
   :source-code: base/protocols/quic/main.zeek 227 233

   :Type: :zeek:type:`Conn::RemovalHook`


.. zeek:id:: QUIC::log_policy
   :source-code: base/protocols/quic/main.zeek 72 72

   :Type: :zeek:type:`Log::PolicyHook`



