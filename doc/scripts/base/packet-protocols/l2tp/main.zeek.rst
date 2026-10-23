:tocdepth: 3

base/packet-protocols/l2tp/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::L2TP


:Namespace: PacketAnalyzer::L2TP

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================= ===========================================
:zeek:id:`PacketAnalyzer::L2TP::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` Default analyzer
:zeek:id:`PacketAnalyzer::L2TP::l2tp_ports`: :zeek:type:`set` :zeek:attr:`&redef`                       The set of UDP ports used for L2TP tunnels.
======================================================================================================= ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::L2TP::default_analyzer
   :source-code: base/packet-protocols/l2tp/main.zeek 5 5

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_PPP``

   Default analyzer

.. zeek:id:: PacketAnalyzer::L2TP::l2tp_ports
   :source-code: base/packet-protocols/l2tp/main.zeek 8 8

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1701/udp
         }


   The set of UDP ports used for L2TP tunnels.


