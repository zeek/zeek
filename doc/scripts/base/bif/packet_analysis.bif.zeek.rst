:tocdepth: 3

base/bif/packet_analysis.bif.zeek
=================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketAnalyzer


:Namespaces: GLOBAL, PacketAnalyzer

Summary
~~~~~~~
Functions
#########
====================================================================================== ==============================================================================================================
:zeek:id:`PacketAnalyzer::__disable_analyzer`: :zeek:type:`function`                   Internal function to disable a packet analyzer.
:zeek:id:`PacketAnalyzer::__enable_analyzer`: :zeek:type:`function`                    Internal function to enable a packet analyzer.
:zeek:id:`PacketAnalyzer::__set_ignore_checksums_nets`: :zeek:type:`function`          Internal function that is used to update the core-mirror of the script-level `ignore_checksums_nets` variable.
:zeek:id:`PacketAnalyzer::register_packet_analyzer`: :zeek:type:`function`             Add an entry to parent's dispatcher that maps a protocol/index to a next-stage child analyzer.
:zeek:id:`PacketAnalyzer::register_protocol_detection`: :zeek:type:`function`          Registers a child analyzer with a parent analyzer to perform packet detection when determining whether
                                                                                       to forward from parent to child.
:zeek:id:`PacketAnalyzer::try_register_packet_analyzer_by_name`: :zeek:type:`function` Attempts to add an entry to `parent`'s dispatcher that maps a protocol/index to a next-stage `child`
                                                                                       analyzer.
====================================================================================== ==============================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketAnalyzer::__disable_analyzer
   :source-code: base/bif/packet_analysis.bif.zeek 41 41

   :Type: :zeek:type:`function` (id: :zeek:type:`PacketAnalyzer::Tag`) : :zeek:type:`bool`

   Internal function to disable a packet analyzer.

.. zeek:id:: PacketAnalyzer::__enable_analyzer
   :source-code: base/bif/packet_analysis.bif.zeek 45 45

   :Type: :zeek:type:`function` (id: :zeek:type:`PacketAnalyzer::Tag`) : :zeek:type:`bool`

   Internal function to enable a packet analyzer.

.. zeek:id:: PacketAnalyzer::__set_ignore_checksums_nets
   :source-code: base/bif/packet_analysis.bif.zeek 29 29

   :Type: :zeek:type:`function` (v: :zeek:type:`subnet_set`) : :zeek:type:`bool`

   Internal function that is used to update the core-mirror of the script-level `ignore_checksums_nets` variable.

.. zeek:id:: PacketAnalyzer::register_packet_analyzer
   :source-code: base/bif/packet_analysis.bif.zeek 15 15

   :Type: :zeek:type:`function` (parent: :zeek:type:`PacketAnalyzer::Tag`, identifier: :zeek:type:`count`, child: :zeek:type:`PacketAnalyzer::Tag`) : :zeek:type:`bool`

   Add an entry to parent's dispatcher that maps a protocol/index to a next-stage child analyzer.
   

   :param parent: The parent analyzer being modified

   :param identifier: The identifier for the protocol being registered

   :param child: The analyzer that will be called for the identifier
   

.. zeek:id:: PacketAnalyzer::register_protocol_detection
   :source-code: base/bif/packet_analysis.bif.zeek 37 37

   :Type: :zeek:type:`function` (parent: :zeek:type:`PacketAnalyzer::Tag`, child: :zeek:type:`PacketAnalyzer::Tag`) : :zeek:type:`bool`

   Registers a child analyzer with a parent analyzer to perform packet detection when determining whether
   to forward from parent to child.
   

   :param parent: The parent analyzer being modified

   :param child: The analyzer that will use protocol detection

.. zeek:id:: PacketAnalyzer::try_register_packet_analyzer_by_name
   :source-code: base/bif/packet_analysis.bif.zeek 25 25

   :Type: :zeek:type:`function` (parent: :zeek:type:`string`, identifier: :zeek:type:`count`, child: :zeek:type:`string`) : :zeek:type:`bool`

   Attempts to add an entry to `parent`'s dispatcher that maps a protocol/index to a next-stage `child`
   analyzer. This may fail if either of the two names does not respond to a known analyzer.
   

   :param parent: The parent analyzer being modified

   :param identifier: The identifier for the protocol being registered

   :param child: The analyzer that will be called for the identifier
   


