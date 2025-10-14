:tocdepth: 3

base/packet-protocols/skip/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::SKIP


:Namespace: PacketAnalyzer::SKIP

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================= ================
:zeek:id:`PacketAnalyzer::SKIP::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
:zeek:id:`PacketAnalyzer::SKIP::skip_bytes`: :zeek:type:`count` :zeek:attr:`&redef`                     Bytes to skip.
======================================================================================================= ================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::SKIP::default_analyzer
   :source-code: base/packet-protocols/skip/main.zeek 5 5

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer

.. zeek:id:: PacketAnalyzer::SKIP::skip_bytes
   :source-code: base/packet-protocols/skip/main.zeek 8 8

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Bytes to skip.


