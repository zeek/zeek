:tocdepth: 3

base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek
==================================================
.. zeek:namespace:: AF_Packet
.. zeek:namespace:: GLOBAL


:Namespaces: AF_Packet, GLOBAL

Summary
~~~~~~~
Types
#####
======================================================= ====================================
:zeek:type:`AF_Packet::ChecksumMode`: :zeek:type:`enum` Available checksum validation modes.
:zeek:type:`AF_Packet::FanoutMode`: :zeek:type:`enum`   Available fanout modes.
======================================================= ====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: AF_Packet::ChecksumMode
   :source-code: base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek 21 21

   :Type: :zeek:type:`enum`

      .. zeek:enum:: AF_Packet::CHECKSUM_OFF AF_Packet::ChecksumMode

         Ignore checksums, i.e. always assume they are correct.

      .. zeek:enum:: AF_Packet::CHECKSUM_ON AF_Packet::ChecksumMode

         Let Zeek compute and verify checksums.

      .. zeek:enum:: AF_Packet::CHECKSUM_KERNEL AF_Packet::ChecksumMode

         Let the kernel handle checksum offloading.
         Note: Semantics may depend on the kernel and driver version.

   Available checksum validation modes.

.. zeek:type:: AF_Packet::FanoutMode
   :source-code: base/bif/plugins/Zeek_AF_Packet.af_packet.bif.zeek 11 11

   :Type: :zeek:type:`enum`

      .. zeek:enum:: AF_Packet::FANOUT_HASH AF_Packet::FanoutMode

      .. zeek:enum:: AF_Packet::FANOUT_CPU AF_Packet::FanoutMode

      .. zeek:enum:: AF_Packet::FANOUT_QM AF_Packet::FanoutMode

      .. zeek:enum:: AF_Packet::FANOUT_CBPF AF_Packet::FanoutMode

      .. zeek:enum:: AF_Packet::FANOUT_EBPF AF_Packet::FanoutMode

   Available fanout modes.


