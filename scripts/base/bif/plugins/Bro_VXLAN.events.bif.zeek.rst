:tocdepth: 3

base/bif/plugins/Bro_VXLAN.events.bif.zeek
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================= ========================================================
:bro:id:`vxlan_packet`: :bro:type:`event` Generated for any packet encapsulated in a VXLAN tunnel.
========================================= ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: vxlan_packet

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`pkt_hdr`, vni: :bro:type:`count`)

   Generated for any packet encapsulated in a VXLAN tunnel.
   See :rfc:`7348` for more information about the VXLAN protocol.
   

   :outer: The VXLAN tunnel connection.
   

   :inner: The VXLAN-encapsulated Ethernet packet header and transport header.
   

   :vni: VXLAN Network Identifier.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


