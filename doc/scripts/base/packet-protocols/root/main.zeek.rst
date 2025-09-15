:tocdepth: 3

base/packet-protocols/root/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::ROOT


:Namespace: PacketAnalyzer::ROOT

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================= ===================================================================
:zeek:id:`PacketAnalyzer::ROOT::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer (if we don't know the link type, we assume raw IP)
======================================================================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::ROOT::default_analyzer
   :source-code: base/packet-protocols/root/main.zeek 5 5

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer (if we don't know the link type, we assume raw IP)


