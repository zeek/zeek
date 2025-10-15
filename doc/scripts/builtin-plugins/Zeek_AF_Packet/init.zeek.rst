:tocdepth: 3

builtin-plugins/Zeek_AF_Packet/init.zeek
========================================
.. zeek:namespace:: AF_Packet

Packet source using AF_Packet.

Note: This module is in testing and is not yet considered stable!

:Namespace: AF_Packet

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================== =====================================================================
:zeek:id:`AF_Packet::block_size`: :zeek:type:`count` :zeek:attr:`&redef`                                 Size of an individual block.
:zeek:id:`AF_Packet::block_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`                           Retire timeout for a single block.
:zeek:id:`AF_Packet::buffer_size`: :zeek:type:`count` :zeek:attr:`&redef`                                Size of the ring-buffer.
:zeek:id:`AF_Packet::checksum_validation_mode`: :zeek:type:`AF_Packet::ChecksumMode` :zeek:attr:`&redef` Checksum validation mode.
:zeek:id:`AF_Packet::enable_defrag`: :zeek:type:`bool` :zeek:attr:`&redef`                               Toggle defragmentation of IP packets using PACKET_FANOUT_FLAG_DEFRAG.
:zeek:id:`AF_Packet::enable_fanout`: :zeek:type:`bool` :zeek:attr:`&redef`                               Toggle whether to use PACKET_FANOUT.
:zeek:id:`AF_Packet::enable_hw_timestamping`: :zeek:type:`bool` :zeek:attr:`&redef`                      Toggle whether to use hardware timestamps.
:zeek:id:`AF_Packet::fanout_id`: :zeek:type:`count` :zeek:attr:`&redef`                                  Fanout ID.
:zeek:id:`AF_Packet::fanout_mode`: :zeek:type:`AF_Packet::FanoutMode` :zeek:attr:`&redef`                Fanout mode.
:zeek:id:`AF_Packet::link_type`: :zeek:type:`count` :zeek:attr:`&redef`                                  Link type (default Ethernet).
======================================================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: AF_Packet::block_size
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 11 11

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``32768``

   Size of an individual block. Needs to be a multiple of page size.

.. zeek:id:: AF_Packet::block_timeout
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 13 13

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 msecs``

   Retire timeout for a single block.

.. zeek:id:: AF_Packet::buffer_size
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 9 9

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``134217728``

   Size of the ring-buffer.

.. zeek:id:: AF_Packet::checksum_validation_mode
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 27 27

   :Type: :zeek:type:`AF_Packet::ChecksumMode`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``AF_Packet::CHECKSUM_ON``

   Checksum validation mode.

.. zeek:id:: AF_Packet::enable_defrag
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 19 19

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggle defragmentation of IP packets using PACKET_FANOUT_FLAG_DEFRAG.

.. zeek:id:: AF_Packet::enable_fanout
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 17 17

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggle whether to use PACKET_FANOUT.

.. zeek:id:: AF_Packet::enable_hw_timestamping
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 15 15

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggle whether to use hardware timestamps.

.. zeek:id:: AF_Packet::fanout_id
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 23 23

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``23``

   Fanout ID.

.. zeek:id:: AF_Packet::fanout_mode
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 21 21

   :Type: :zeek:type:`AF_Packet::FanoutMode`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``AF_Packet::FANOUT_HASH``

   Fanout mode.

.. zeek:id:: AF_Packet::link_type
   :source-code: builtin-plugins/Zeek_AF_Packet/init.zeek 25 25

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Link type (default Ethernet).


