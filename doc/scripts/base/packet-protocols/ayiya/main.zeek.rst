:tocdepth: 3

base/packet-protocols/ayiya/main.zeek
=====================================
.. zeek:namespace:: PacketAnalyzer::AYIYA


:Namespace: PacketAnalyzer::AYIYA
:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================== ============================================
:zeek:id:`PacketAnalyzer::AYIYA::ayiya_ports`: :zeek:type:`set` :zeek:attr:`&redef` The set of UDP ports used for AYIYA tunnels.
=================================================================================== ============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::AYIYA::ayiya_ports
   :source-code: base/packet-protocols/ayiya/main.zeek 11 11

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            5072/udp
         }


   The set of UDP ports used for AYIYA tunnels.


