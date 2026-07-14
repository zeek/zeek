:tocdepth: 3

base/bif/plugins/Zeek_PacketSourceUDP.packet_source_udp.bif.zeek
================================================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketSource::UDP


:Namespaces: GLOBAL, PacketSource::UDP

Summary
~~~~~~~
Types
#####
========================================================================= =
:zeek:type:`PacketSource::UDP::ReceiverImplementation`: :zeek:type:`enum`
========================================================================= =

Functions
#########
======================================================================= =======================================================================
:zeek:id:`PacketSource::UDP::get_geneve_options`: :zeek:type:`function` Get the GENVE options as :zeek:see:`geneve_options_vec` as stashed away
                                                                        by the PacketSource::UDP implementation.
======================================================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: PacketSource::UDP::ReceiverImplementation
   :source-code: base/bif/plugins/Zeek_PacketSourceUDP.packet_source_udp.bif.zeek 7 7

   :Type: :zeek:type:`enum`

      .. zeek:enum:: PacketSource::UDP::RECVMMSG PacketSource::UDP::ReceiverImplementation

      .. zeek:enum:: PacketSource::UDP::IO_URING PacketSource::UDP::ReceiverImplementation


Functions
#########
.. zeek:id:: PacketSource::UDP::get_geneve_options
   :source-code: base/bif/plugins/Zeek_PacketSourceUDP.packet_source_udp.bif.zeek 32 32

   :Type: :zeek:type:`function` () : :zeek:type:`geneve_options_vec`

   Get the GENVE options as :zeek:see:`geneve_options_vec` as stashed away
   by the PacketSource::UDP implementation.


