:tocdepth: 3

base/packet-protocols/teredo/main.zeek
======================================
.. zeek:namespace:: PacketAnalyzer::TEREDO


:Namespace: PacketAnalyzer::TEREDO
:Imports: :doc:`base/bif/plugins/Zeek_Teredo.events.bif.zeek </scripts/base/bif/plugins/Zeek_Teredo.events.bif.zeek>`, :doc:`base/bif/plugins/Zeek_Teredo.functions.bif.zeek </scripts/base/bif/plugins/Zeek_Teredo.functions.bif.zeek>`, :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================================= =============================================
:zeek:id:`PacketAnalyzer::TEREDO::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
:zeek:id:`PacketAnalyzer::TEREDO::teredo_ports`: :zeek:type:`set` :zeek:attr:`&redef`                     The set of UDP ports used for Teredo tunnels.
========================================================================================================= =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::TEREDO::default_analyzer
   :source-code: base/packet-protocols/teredo/main.zeek 17 17

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer

.. zeek:id:: PacketAnalyzer::TEREDO::teredo_ports
   :source-code: base/packet-protocols/teredo/main.zeek 20 20

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            3544/udp
         }


   The set of UDP ports used for Teredo tunnels.


