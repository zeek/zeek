:tocdepth: 3

base/packet-protocols/gre/main.zeek
===================================
.. zeek:namespace:: PacketAnalyzer::GRE


:Namespace: PacketAnalyzer::GRE

Summary
~~~~~~~
Redefinable Options
###################
====================================================================================================== =
:zeek:id:`PacketAnalyzer::GRE::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` 
:zeek:id:`PacketAnalyzer::GRE::gre_ports`: :zeek:type:`set` :zeek:attr:`&redef`                        
====================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::GRE::default_analyzer
   :source-code: base/packet-protocols/gre/main.zeek 4 4

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IPTUNNEL``


.. zeek:id:: PacketAnalyzer::GRE::gre_ports
   :source-code: base/packet-protocols/gre/main.zeek 5 5

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            4754/udp
         }




