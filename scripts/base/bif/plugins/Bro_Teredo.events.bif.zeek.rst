:tocdepth: 3

base/bif/plugins/Bro_Teredo.events.bif.zeek
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
===================================================== ===============================================================
:bro:id:`teredo_authentication`: :bro:type:`event`    Generated for IPv6 packets encapsulated in a Teredo tunnel that
                                                      use the Teredo authentication encapsulation method.
:bro:id:`teredo_bubble`: :bro:type:`event`            Generated for Teredo bubble packets.
:bro:id:`teredo_origin_indication`: :bro:type:`event` Generated for IPv6 packets encapsulated in a Teredo tunnel that
                                                      use the Teredo origin indication encapsulation method.
:bro:id:`teredo_packet`: :bro:type:`event`            Generated for any IPv6 packet encapsulated in a Teredo tunnel.
===================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: teredo_authentication

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo authentication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_bubble

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for Teredo bubble packets.  That is, IPv6 packets encapsulated
   in a Teredo tunnel that have a Next Header value of :bro:id:`IPPROTO_NONE`.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_authentication teredo_origin_indication
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_origin_indication

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo origin indication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_authentication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_packet

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for any IPv6 packet encapsulated in a Teredo tunnel.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_authentication teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.


