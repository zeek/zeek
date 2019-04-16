:tocdepth: 3

base/bif/plugins/Bro_Gnutella.events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== =====
:bro:id:`gnutella_binary_msg`: :bro:type:`event`         TODO.
:bro:id:`gnutella_establish`: :bro:type:`event`          TODO.
:bro:id:`gnutella_http_notify`: :bro:type:`event`        TODO.
:bro:id:`gnutella_not_establish`: :bro:type:`event`      TODO.
:bro:id:`gnutella_partial_binary_msg`: :bro:type:`event` TODO.
:bro:id:`gnutella_text_msg`: :bro:type:`event`           TODO.
======================================================== =====


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: gnutella_binary_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, msg_type: :bro:type:`count`, ttl: :bro:type:`count`, hops: :bro:type:`count`, msg_len: :bro:type:`count`, payload: :bro:type:`string`, payload_len: :bro:type:`count`, trunc: :bro:type:`bool`, complete: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_establish gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_establish

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg  gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_http_notify

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_not_establish

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_partial_binary_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, msg: :bro:type:`string`, len: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish  gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_text_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, headers: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see::  gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish gnutella_partial_binary_msg gnutella_signature_found
   
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


