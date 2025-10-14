:tocdepth: 3

base/bif/plugins/Zeek_GTPv1.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================ ===========================================================
:zeek:id:`gtpv1_create_pdp_ctx_request`: :zeek:type:`event`  Generated for GTPv1-C Create PDP Context Request messages.
:zeek:id:`gtpv1_create_pdp_ctx_response`: :zeek:type:`event` Generated for GTPv1-C Create PDP Context Response messages.
:zeek:id:`gtpv1_delete_pdp_ctx_request`: :zeek:type:`event`  Generated for GTPv1-C Delete PDP Context Request messages.
:zeek:id:`gtpv1_delete_pdp_ctx_response`: :zeek:type:`event` Generated for GTPv1-C Delete PDP Context Response messages.
:zeek:id:`gtpv1_g_pdu_packet`: :zeek:type:`event`            Generated for GTPv1 G-PDU packets.
:zeek:id:`gtpv1_message`: :zeek:type:`event`                 Generated for any GTP message with a GTPv1 header.
:zeek:id:`gtpv1_update_pdp_ctx_request`: :zeek:type:`event`  Generated for GTPv1-C Update PDP Context Request messages.
:zeek:id:`gtpv1_update_pdp_ctx_response`: :zeek:type:`event` Generated for GTPv1-C Update PDP Context Response messages.
============================================================ ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: gtpv1_create_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_create_pdp_ctx_request_elements`)

   Generated for GTPv1-C Create PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_create_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_create_pdp_ctx_response_elements`)

   Generated for GTPv1-C Create PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_delete_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 73 73

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_delete_pdp_ctx_request_elements`)

   Generated for GTPv1-C Delete PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_delete_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 83 83

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_delete_pdp_ctx_response_elements`)

   Generated for GTPv1-C Delete PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_g_pdu_packet
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 23 23

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner_gtp: :zeek:type:`gtpv1_hdr`, inner_ip: :zeek:type:`pkt_hdr`)

   Generated for GTPv1 G-PDU packets.  That is, packets with a UDP payload
   that includes a GTP header followed by an IPv4 or IPv6 packet.
   

   :param outer: The GTP outer tunnel connection.
   

   :param inner_gtp: The GTP header.
   

   :param inner_ip: The inner IP and transport layer packet headers.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: gtpv1_message
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 9 9

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`)

   Generated for any GTP message with a GTPv1 header.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.

.. zeek:id:: gtpv1_update_pdp_ctx_request
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 53 53

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_update_pdp_ctx_request_elements`)

   Generated for GTPv1-C Update PDP Context Request messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.

.. zeek:id:: gtpv1_update_pdp_ctx_response
   :source-code: base/bif/plugins/Zeek_GTPv1.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`gtpv1_hdr`, elements: :zeek:type:`gtp_update_pdp_ctx_response_elements`)

   Generated for GTPv1-C Update PDP Context Response messages.
   

   :param c: The connection over which the message is sent.
   

   :param hdr: The GTPv1 header.
   

   :param elements: The set of Information Elements comprising the message.


