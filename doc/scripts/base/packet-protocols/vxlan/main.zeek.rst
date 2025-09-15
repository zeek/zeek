:tocdepth: 3

base/packet-protocols/vxlan/main.zeek
=====================================
.. zeek:namespace:: PacketAnalyzer::VXLAN


:Namespace: PacketAnalyzer::VXLAN

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================== ============================================
:zeek:id:`PacketAnalyzer::VXLAN::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef` 
:zeek:id:`PacketAnalyzer::VXLAN::vxlan_ports`: :zeek:type:`set` :zeek:attr:`&redef`                      The set of UDP ports used for VXLAN traffic.
======================================================================================================== ============================================

Redefinitions
#############
==================================================================== =
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::VXLAN::default_analyzer
   :source-code: base/packet-protocols/vxlan/main.zeek 6 6

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_ETHERNET``


.. zeek:id:: PacketAnalyzer::VXLAN::vxlan_ports
   :source-code: base/packet-protocols/vxlan/main.zeek 12 12

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            4789/udp
         }


   The set of UDP ports used for VXLAN traffic.  Traffic using this
   UDP destination port will attempt to be decapsulated.  Note that if
   if you customize this, you may still want to manually ensure that
   :zeek:see:`likely_server_ports` also gets populated accordingly.


