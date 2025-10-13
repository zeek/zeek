Packet Analyzers
================

.. zeek:type:: PacketAnalyzer::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ARP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_AYIYA PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ETHERNET PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_FDDI PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_GENEVE PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_GRE PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_GTPV1 PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ICMP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IEEE802_11 PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IEEE802_11_RADIO PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IPTUNNEL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_LINUXSLL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_LINUXSLL2 PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_LLC PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_MPLS PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_NFLOG PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_NOVELL_802_3 PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_NULL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PBB PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PPP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PPPOE PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PPPSERIAL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ROOT PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_SKIP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_SNAP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_TCP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_TEREDO PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_UDP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_VLAN PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_VNTAG PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_VXLAN PacketAnalyzer::Tag

.. _plugin-zeek-arp:

Zeek::ARP
---------

ARP packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ARP`

Events
++++++

.. zeek:id:: arp_request
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 22 22

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :param mac_src: The request's source MAC address.
   

   :param mac_dst: The request's destination MAC address.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   
   .. zeek:see:: arp_reply  bad_arp

.. zeek:id:: arp_reply
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :param mac_src: The reply's source MAC address.
   

   :param mac_dst: The reply's destination MAC address.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   
   .. zeek:see::  arp_request bad_arp

.. zeek:id:: bad_arp
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 66 66

   :Type: :zeek:type:`event` (SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`, explanation: :zeek:type:`string`)

   Generated for ARP packets that Zeek cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   

   :param explanation: A short description of why the ARP packet is considered "bad".
   
   .. zeek:see:: arp_reply arp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-ayiya:

Zeek::AYIYA
-----------

AYIYA packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_AYIYA`

.. _plugin-zeek-ethernet:

Zeek::Ethernet
--------------

Ethernet packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ETHERNET`

.. _plugin-zeek-fddi:

Zeek::FDDI
----------

FDDI packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_FDDI`

.. _plugin-zeek-geneve:

Zeek::Geneve
------------

Geneve packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_GENEVE`

Events
++++++

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

Functions
+++++++++

.. zeek:id:: PacketAnalyzer::Geneve::get_options
   :source-code: base/bif/plugins/Zeek_Geneve.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` () : :zeek:type:`geneve_options_vec_vec`

   Returns all Geneve options from all layers of the current packet.
   
   The last entry in the outer vector are the options of the most
   inner Geneve header.
   
   Returns a vector of vector of :zeek:see:`PacketAnalyzer::Geneve::Option` records.

.. _plugin-zeek-gre:

Zeek::GRE
---------

GRE packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_GRE`

.. _plugin-zeek-gtpv1:

Zeek::GTPv1
-----------

GTPv1 analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_GTPV1`

Events
++++++

.. zeek:id:: new_gtpv1_state
   :source-code: base/packet-protocols/gtpv1/main.zeek 35 38

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a new GTP analyzer is instantiated for a connection.
   
   This event exists to install a connection removal hook to clear
   internal per-connection GTPv1 state.
   

   :param c: The connection for which the analyzer is instantiated.

.. zeek:id:: gtpv1_message
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`)

   Generated for any GTP message with a GTPv1 header.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.

.. zeek:id:: gtpv1_g_pdu_packet
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 35 35

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner_gtp: :zeek:type:`gtpv1_hdr`, inner_ip: :zeek:type:`pkt_hdr`)

   Generated for GTPv1 G-PDU packets.  That is, packets with a UDP payload
   that includes a GTP header followed by an IPv4 or IPv6 packet.
   

   :param outer: The GTP outer tunnel connection.
   

   :param inner_gtp: The GTP header.
   

   :param inner_ip: The inner IP and transport layer packet headers.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: gtpv1_create_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_create_pdp_ctx_request_elements`)

   Generated for GTPv1-C Create PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_create_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 55 55

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_create_pdp_ctx_response_elements`)

   Generated for GTPv1-C Create PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_update_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 65 65

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_update_pdp_ctx_request_elements`)

   Generated for GTPv1-C Update PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_update_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 75 75

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_update_pdp_ctx_response_elements`)

   Generated for GTPv1-C Update PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_delete_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 85 85

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_delete_pdp_ctx_request_elements`)

   Generated for GTPv1-C Delete PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_delete_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 95 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_delete_pdp_ctx_response_elements`)

   Generated for GTPv1-C Delete PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

Functions
+++++++++

.. zeek:id:: PacketAnalyzer::GTPV1::remove_gtpv1_connection
   :source-code: base/bif/plugins/Zeek_GTPv1.functions.bif.zeek 9 9

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`bool`


.. _plugin-zeek-ieee802-11:

Zeek::IEEE802_11
----------------

IEEE 802.11 packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IEEE802_11`

.. _plugin-zeek-ieee802-11-radio:

Zeek::IEEE802_11_Radio
----------------------

IEEE 802.11 Radiotap packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IEEE802_11_RADIO`

.. _plugin-zeek-ip:

Zeek::IP
--------

Packet analyzer for IP fallback (v4 or v6)

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IP`

.. _plugin-zeek-iptunnel:

Zeek::IPTunnel
--------------

IPTunnel packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IPTUNNEL`

.. _plugin-zeek-linuxsll:

Zeek::LinuxSLL
--------------

Linux cooked capture (SLL) packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_LINUXSLL`

.. _plugin-zeek-linuxsll2:

Zeek::LinuxSLL2
---------------

Linux cooked capture version 2 (SLL2) packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_LINUXSLL2`

.. _plugin-zeek-llc:

Zeek::LLC
---------

LLC packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_LLC`

.. _plugin-zeek-mpls:

Zeek::MPLS
----------

MPLS packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_MPLS`

.. _plugin-zeek-nflog:

Zeek::NFLog
-----------

NFLog packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_NFLOG`

.. _plugin-zeek-novell-802-3:

Zeek::NOVELL_802_3
------------------

Novell 802.3 variantx packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_NOVELL_802_3`

.. _plugin-zeek-null:

Zeek::Null
----------

Null packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_NULL`

.. _plugin-zeek-pbb:

Zeek::PBB
---------

PBB packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PBB`

.. _plugin-zeek-ppp:

Zeek::PPP
---------

PPP packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PPP`

.. _plugin-zeek-pppoe:

Zeek::PPPoE
-----------

PPPoE packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PPPOE`

Functions
+++++++++

.. zeek:id:: PacketAnalyzer::PPPoE::session_id
   :source-code: base/bif/plugins/Zeek_PPPoE.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns the PPPoE Session ID of the current packet, if present.
   
   If no PPPoE Session ID is present, 0xFFFFFFFF is returned, which
   is out of range of the session ID.
   

   :returns: The PPPoE session ID if present, 0xFFFFFFFF otherwise.

.. _plugin-zeek-pppserial:

Zeek::PPPSerial
---------------

PPPSerial packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PPPSERIAL`

.. _plugin-zeek-root:

Zeek::Root
----------

Root packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ROOT`

.. _plugin-zeek-skip:

Zeek::Skip
----------

Skip packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_SKIP`

.. _plugin-zeek-snap:

Zeek::SNAP
----------

SNAP packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_SNAP`

.. _plugin-zeek-teredo:

Zeek::Teredo
------------

Teredo packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_TEREDO`

Events
++++++

.. zeek:id:: teredo_packet
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 18 18

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for any IPv6 packet encapsulated in a Teredo tunnel.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_authentication teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: new_teredo_state
   :source-code: base/packet-protocols/teredo/main.zeek 36 39

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when per connection Teredo state is created.
   
   This is primarily useful to install a connection removal hook to clear
   internal per-connection Teredo state.
   

   :param c: The Teredo tunnel connection.

.. zeek:id:: teredo_authentication
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 42 42

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo authentication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: teredo_origin_indication
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 57 57

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo origin indication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_authentication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: teredo_bubble
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 72 72

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for Teredo bubble packets.  That is, IPv6 packets encapsulated
   in a Teredo tunnel that have a Next Header value of :zeek:id:`IPPROTO_NONE`.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_authentication teredo_origin_indication
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

Functions
+++++++++

.. zeek:id:: PacketAnalyzer::TEREDO::remove_teredo_connection
   :source-code: base/bif/plugins/Zeek_Teredo.functions.bif.zeek 9 9

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`bool`


.. _plugin-zeek-vlan:

Zeek::VLAN
----------

VLAN packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_VLAN`

.. _plugin-zeek-vntag:

Zeek::VNTag
-----------

VNTag packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_VNTAG`

.. _plugin-zeek-vxlan:

Zeek::VXLAN
-----------

VXLAN packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_VXLAN`

Events
++++++

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

