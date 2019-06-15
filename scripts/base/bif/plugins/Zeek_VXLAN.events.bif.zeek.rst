:tocdepth: 3

base/bif/plugins/Zeek_VXLAN.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================== ========================================================
:zeek:id:`vxlan_packet`: :zeek:type:`event` Generated for any packet encapsulated in a VXLAN tunnel.
=========================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: vxlan_packet

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`pkt_hdr`, vni: :zeek:type:`count`)

   Generated for any packet encapsulated in a VXLAN tunnel.
   See :rfc:`7348` for more information about the VXLAN protocol.
   

   :outer: The VXLAN tunnel connection.
   

   :inner: The VXLAN-encapsulated Ethernet packet header and transport header.
   

   :vni: VXLAN Network Identifier.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


