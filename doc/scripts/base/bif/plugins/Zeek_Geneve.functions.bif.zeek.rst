:tocdepth: 3

base/bif/plugins/Zeek_Geneve.functions.bif.zeek
===============================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketAnalyzer::Geneve


:Namespaces: GLOBAL, PacketAnalyzer::Geneve

Summary
~~~~~~~
Functions
#########
===================================================================== =================================================================
:zeek:id:`PacketAnalyzer::Geneve::get_options`: :zeek:type:`function` Returns all Geneve options from all layers of the current packet.
===================================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketAnalyzer::Geneve::get_options
   :source-code: base/bif/plugins/Zeek_Geneve.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` () : :zeek:type:`geneve_options_vec_vec`

   Returns all Geneve options from all layers of the current packet.

   The last entry in the outer vector are the options of the most
   inner Geneve header.

   Returns a vector of vector of :zeek:see:`PacketAnalyzer::Geneve::Option` records.


