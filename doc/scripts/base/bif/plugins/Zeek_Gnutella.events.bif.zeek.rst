:tocdepth: 3

base/bif/plugins/Zeek_Gnutella.events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== =====
:zeek:id:`gnutella_binary_msg`: :zeek:type:`event`         TODO.
:zeek:id:`gnutella_establish`: :zeek:type:`event`          TODO.
:zeek:id:`gnutella_http_notify`: :zeek:type:`event`        TODO.
:zeek:id:`gnutella_not_establish`: :zeek:type:`event`      TODO.
:zeek:id:`gnutella_partial_binary_msg`: :zeek:type:`event` TODO.
:zeek:id:`gnutella_text_msg`: :zeek:type:`event`           TODO.
========================================================== =====


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: gnutella_binary_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 32 32

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, msg_type: :zeek:type:`count`, ttl: :zeek:type:`count`, hops: :zeek:type:`count`, msg_len: :zeek:type:`count`, payload: :zeek:type:`string`, payload_len: :zeek:type:`count`, trunc: :zeek:type:`bool`, complete: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_establish gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_establish
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg  gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_http_notify
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_not_establish
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 77 77

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_partial_binary_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 47 47

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, msg: :zeek:type:`string`, len: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish  gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_text_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, headers: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see::  gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish gnutella_partial_binary_msg
   
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


