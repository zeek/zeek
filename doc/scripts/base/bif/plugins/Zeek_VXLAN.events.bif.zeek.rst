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
   :source-code: base/bif/plugins/Zeek_VXLAN.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`pkt_hdr`, vni: :zeek:type:`count`)

   Generated for any packet encapsulated in a VXLAN tunnel.
   See :rfc:`7348` for more information about the VXLAN protocol.
   

   :param outer: The VXLAN tunnel connection.
   

   :param inner: The VXLAN-encapsulated Ethernet packet header and transport header.
   

   :param vni: VXLAN Network Identifier.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


