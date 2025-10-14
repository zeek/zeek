:tocdepth: 3

base/packet-protocols/geneve/main.zeek
======================================
.. zeek:namespace:: PacketAnalyzer::Geneve


:Namespace: PacketAnalyzer::Geneve

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== =============================================
:zeek:id:`PacketAnalyzer::Geneve::geneve_ports`: :zeek:type:`set` :zeek:attr:`&redef` The set of UDP ports used for Geneve traffic.
===================================================================================== =============================================

Redefinitions
#############
==================================================================== =
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::Geneve::geneve_ports
   :source-code: base/packet-protocols/geneve/main.zeek 8 8

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            6081/udp
         }


   The set of UDP ports used for Geneve traffic.  Traffic using this
   UDP destination port will attempt to be decapsulated.  Note that if
   if you customize this, you may still want to manually ensure that
   :zeek:see:`likely_server_ports` also gets populated accordingly.


