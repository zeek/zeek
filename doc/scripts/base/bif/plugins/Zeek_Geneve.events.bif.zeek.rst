:tocdepth: 3

base/bif/plugins/Zeek_Geneve.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================ =========================================================
:zeek:id:`geneve_packet`: :zeek:type:`event` Generated for any packet encapsulated in a Geneve tunnel.
============================================ =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: geneve_packet
   :source-code: base/bif/plugins/Zeek_Geneve.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`pkt_hdr`, vni: :zeek:type:`count`)

   Generated for any packet encapsulated in a Geneve tunnel.
   See :rfc:`8926` for more information about the Geneve protocol.
   

   :param outer: The Geneve tunnel connection.
   

   :param inner: The Geneve-encapsulated Ethernet packet header and transport header.
   

   :param vni: Geneve Network Identifier.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


