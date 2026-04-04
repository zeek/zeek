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
======================================================================================================== ============================================
:zeek:id:`PacketAnalyzer::GTPV1::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
:zeek:id:`PacketAnalyzer::GTPV1::gtpv1_ports`: :zeek:type:`set` :zeek:attr:`&redef`                      The set of UDP ports used for GTPV1 tunnels.
======================================================================================================== ============================================


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

.. zeek:id:: PacketAnalyzer::GTPV1::gtpv1_ports
   :source-code: base/packet-protocols/gtpv1/main.zeek 20 20

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            2152/udp,
            2123/udp
         }


   The set of UDP ports used for GTPV1 tunnels.


