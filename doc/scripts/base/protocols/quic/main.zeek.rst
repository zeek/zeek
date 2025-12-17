:tocdepth: 3

base/protocols/quic/main.zeek
=============================
.. zeek:namespace:: QUIC

Implements base functionality for QUIC analysis. Generates quic.log.

:Namespace: QUIC
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/quic/consts.zeek </scripts/base/protocols/quic/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ========================================
:zeek:id:`QUIC::max_history_length`: :zeek:type:`count` :zeek:attr:`&redef` The maximum length of the history field.
=========================================================================== ========================================

Redefinable Options
###################
================================================================================== ==============================================================
:zeek:id:`QUIC::doq_ports`: :zeek:type:`set` :zeek:attr:`&redef`                   Well-known ports for DNS-over-QUIC.
:zeek:id:`QUIC::max_discarded_packet_events`: :zeek:type:`int` :zeek:attr:`&redef` Maximum number of QUIC::discarded packet() events to generate.
:zeek:id:`QUIC::quic_ports`: :zeek:type:`set` :zeek:attr:`&redef`                  Well-known ports for QUIC.
================================================================================== ==============================================================

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
   :source-code: base/protocols/quic/main.zeek 101 101

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum length of the history field.

Redefinable Options
###################
.. zeek:id:: QUIC::doq_ports
   :source-code: base/protocols/quic/main.zeek 28 28

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            784/udp,
            853/udp
         }


   Well-known ports for DNS-over-QUIC.
   
   Currently not added to likely_server_ports to avoid spurious
   originator/responder changes in the private testing baseline.
   
   You can always add these to likely_server_ports in your local.zeek
   file for your environment if needed:
   
   	redef likely_server_ports += { 853/udp, 784/udp };
   

.. zeek:id:: QUIC::max_discarded_packet_events
   :source-code: base/protocols/quic/main.zeek 105 105

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   Maximum number of QUIC::discarded packet() events to generate.
   Set to 0 for unlimited, -1 for disabled.

.. zeek:id:: QUIC::quic_ports
   :source-code: base/protocols/quic/main.zeek 14 14

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            443/udp
         }


   Well-known ports for QUIC.

Types
#####
.. zeek:type:: QUIC::Info
   :source-code: base/protocols/quic/main.zeek 33 92

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of first QUIC packet for this entry.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: version :zeek:type:`string` :zeek:attr:`&log`

      QUIC version as found in the first INITIAL packet from
      the client. This will often be "1" or "quicv2", but see
      the :zeek:see:`QUIC::version_strings` table for details.


   .. zeek:field:: client_initial_dcid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      First Destination Connection ID used by client. This is
      random and unpredictable, but used for packet protection
      by client and server.


   .. zeek:field:: client_scid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Client's Source Connection ID from the first INITIAL packet.


   .. zeek:field:: server_scid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Server chosen Connection ID usually from server's first
      INITIAL packet. This is to be used by the client in
      subsequent packets.


   .. zeek:field:: server_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Server name extracted from SNI extension in ClientHello
      packet if available.


   .. zeek:field:: client_protocol :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      First protocol extracted from ALPN extension in ClientHello
      packet if available.


   .. zeek:field:: history :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      QUIC history.
      
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
      U       Unfamiliar QUIC version
      X       Discarded packet after successful decryption of INITIAL packets
      O       Short header packets in binary logarithmic fashion
      ======  ====================================================


   .. zeek:field:: history_state :zeek:type:`vector` of :zeek:type:`string`


   .. zeek:field:: logged :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`



Events
######
.. zeek:id:: QUIC::log_quic
   :source-code: base/protocols/quic/main.zeek 94 94

   :Type: :zeek:type:`event` (rec: :zeek:type:`QUIC::Info`)


Hooks
#####
.. zeek:id:: QUIC::finalize_quic
   :source-code: base/protocols/quic/main.zeek 276 282

   :Type: :zeek:type:`Conn::RemovalHook`


.. zeek:id:: QUIC::log_policy
   :source-code: base/protocols/quic/main.zeek 96 96

   :Type: :zeek:type:`Log::PolicyHook`



