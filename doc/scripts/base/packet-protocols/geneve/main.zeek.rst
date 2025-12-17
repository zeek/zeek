:tocdepth: 3

base/packet-protocols/geneve/main.zeek
======================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketAnalyzer::Geneve


:Namespaces: GLOBAL, PacketAnalyzer::Geneve

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== =============================================
:zeek:id:`PacketAnalyzer::Geneve::geneve_ports`: :zeek:type:`set` :zeek:attr:`&redef` The set of UDP ports used for Geneve traffic.
===================================================================================== =============================================

Types
#####
================================================================ ================
:zeek:type:`PacketAnalyzer::Geneve::Option`: :zeek:type:`record` A Geneve option.
:zeek:type:`geneve_options_vec`: :zeek:type:`vector`             
:zeek:type:`geneve_options_vec_vec`: :zeek:type:`vector`         
================================================================ ================


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

Types
#####
.. zeek:type:: PacketAnalyzer::Geneve::Option
   :source-code: base/packet-protocols/geneve/main.zeek 11 20

   :Type: :zeek:type:`record`


   .. zeek:field:: class :zeek:type:`count`

      The class of the option.


   .. zeek:field:: critical :zeek:type:`bool`

      The critical bit of the type.


   .. zeek:field:: typ :zeek:type:`count`

      The type field of the option with the critical bit masked.


   .. zeek:field:: data :zeek:type:`string`

      The data field of the option.


   A Geneve option.

.. zeek:type:: geneve_options_vec
   :source-code: base/packet-protocols/geneve/main.zeek 41 41

   :Type: :zeek:type:`vector` of :zeek:type:`PacketAnalyzer::Geneve::Option`


.. zeek:type:: geneve_options_vec_vec
   :source-code: base/packet-protocols/geneve/main.zeek 42 42

   :Type: :zeek:type:`vector` of :zeek:type:`geneve_options_vec`



