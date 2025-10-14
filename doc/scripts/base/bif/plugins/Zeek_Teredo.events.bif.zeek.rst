:tocdepth: 3

base/bif/plugins/Zeek_Teredo.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ===============================================================
:zeek:id:`teredo_authentication`: :zeek:type:`event`    Generated for IPv6 packets encapsulated in a Teredo tunnel that
                                                        use the Teredo authentication encapsulation method.
:zeek:id:`teredo_bubble`: :zeek:type:`event`            Generated for Teredo bubble packets.
:zeek:id:`teredo_origin_indication`: :zeek:type:`event` Generated for IPv6 packets encapsulated in a Teredo tunnel that
                                                        use the Teredo origin indication encapsulation method.
:zeek:id:`teredo_packet`: :zeek:type:`event`            Generated for any IPv6 packet encapsulated in a Teredo tunnel.
======================================================= ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: teredo_authentication
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 30 30

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo authentication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: teredo_bubble
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 60 60

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for Teredo bubble packets.  That is, IPv6 packets encapsulated
   in a Teredo tunnel that have a Next Header value of :zeek:id:`IPPROTO_NONE`.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_authentication teredo_origin_indication
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: teredo_origin_indication
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo origin indication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_packet teredo_authentication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. zeek:id:: teredo_packet
   :source-code: base/bif/plugins/Zeek_Teredo.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (outer: :zeek:type:`connection`, inner: :zeek:type:`teredo_hdr`)

   Generated for any IPv6 packet encapsulated in a Teredo tunnel.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :param outer: The Teredo tunnel connection.
   

   :param inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. zeek:see:: teredo_authentication teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


