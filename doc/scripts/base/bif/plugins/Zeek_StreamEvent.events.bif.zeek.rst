:tocdepth: 3

base/bif/plugins/Zeek_StreamEvent.events.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ======================================================================
:zeek:id:`stream_deliver`: :zeek:type:`event`     Generated for each chunk of reassembled TCP payload.
:zeek:id:`stream_undelivered`: :zeek:type:`event` Generated when Zeek detects a gap in a reassembled TCP payload stream.
================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: stream_deliver
   :source-code: base/bif/plugins/Zeek_StreamEvent.events.bif.zeek 23 23

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for each chunk of reassembled TCP payload.
   
   This is a low-level event to inspect stream data from the originator
   and responder endpoints. This can be useful for debugging purposes, or
   for logging of plain-text interactive sessions when no more appropriate
   analyzer is available.
   
   Note that this event is potentially expensive if connections that have
   the stream event analyzer attached carry significant amounts of data.
   Generally, a native protocol parser will have much less overhead than
   passing the complete stream data to the scripting layer.
   

   :param c: The connection.
   

   :param is_orig: T if stream data is from the originator-side, else F.
   

   :param data: The raw payload.
   
   .. zeek:see:: stream_undelivered tcp_contents

.. zeek:id:: stream_undelivered
   :source-code: base/bif/plugins/Zeek_StreamEvent.events.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, seq: :zeek:type:`count`, len: :zeek:type:`count`)

   Generated when Zeek detects a gap in a reassembled TCP payload stream.
   

   :param c: The connection.
   

   :param is_orig: T if the gap is in the originator-side input, else F.
   

   :param seq: The sequence number of the first byte of the gap.
   

   :param len: The length of the gap.
   
   .. zeek:see:: stream_deliver content_gap


