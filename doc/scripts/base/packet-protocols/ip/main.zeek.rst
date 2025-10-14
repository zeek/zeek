:tocdepth: 3

base/packet-protocols/ip/main.zeek
==================================
.. zeek:namespace:: PacketAnalyzer::IP


:Namespace: PacketAnalyzer::IP

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================================== ================
:zeek:id:`PacketAnalyzer::IP::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
===================================================================================================== ================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::IP::default_analyzer
   :source-code: base/packet-protocols/ip/main.zeek 5 5

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT``

   Default analyzer


