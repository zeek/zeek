:tocdepth: 3

base/bif/plugins/Zeek_PPPoE.functions.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketAnalyzer::PPPoE


:Namespaces: GLOBAL, PacketAnalyzer::PPPoE

Summary
~~~~~~~
Functions
#########
=================================================================== ===============================================================
:zeek:id:`PacketAnalyzer::PPPoE::session_id`: :zeek:type:`function` Returns the PPPoE Session ID of the current packet, if present.
=================================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketAnalyzer::PPPoE::session_id
   :source-code: base/bif/plugins/Zeek_PPPoE.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns the PPPoE Session ID of the current packet, if present.
   
   If no PPPoE Session ID is present, 0xFFFFFFFF is returned, which
   is out of range of the session ID.
   

   :returns: The PPPoE session ID if present, 0xFFFFFFFF otherwise.


