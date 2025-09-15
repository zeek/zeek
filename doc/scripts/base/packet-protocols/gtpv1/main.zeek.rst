:tocdepth: 3

base/packet-protocols/gtpv1/main.zeek
=====================================
.. zeek:namespace:: PacketAnalyzer::GTPV1


:Namespace: PacketAnalyzer::GTPV1
:Imports: :doc:`base/bif/plugins/Zeek_GTPv1.events.bif.zeek </scripts/base/bif/plugins/Zeek_GTPv1.events.bif.zeek>`, :doc:`base/bif/plugins/Zeek_GTPv1.functions.bif.zeek </scripts/base/bif/plugins/Zeek_GTPv1.functions.bif.zeek>`, :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================== ================
:zeek:id:`PacketAnalyzer::GTPV1::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
======================================================================================================== ================

Redefinitions
#############
==================================================================== =
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::GTPV1::default_analyzer
   :source-code: base/packet-protocols/gtpv1/main.zeek 17 17

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer


