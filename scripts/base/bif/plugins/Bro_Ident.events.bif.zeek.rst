:tocdepth: 3

base/bif/plugins/Bro_Ident.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================ ==================================
:zeek:id:`ident_error`: :zeek:type:`event`   Generated for Ident error replies.
:zeek:id:`ident_reply`: :zeek:type:`event`   Generated for Ident replies.
:zeek:id:`ident_request`: :zeek:type:`event` Generated for Ident requests.
============================================ ==================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: ident_error

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, line: :zeek:type:`string`)

   Generated for Ident error replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :line: The error description returned by the reply.
   
   .. zeek:see:: ident_reply ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, user_id: :zeek:type:`string`, system: :zeek:type:`string`)

   Generated for Ident replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :user_id: The user id returned by the reply.
   

   :system: The operating system returned by the reply.
   
   .. zeek:see:: ident_error  ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`)

   Generated for Ident requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The request's local port.
   

   :rport: The request's remote port.
   
   .. zeek:see:: ident_error ident_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


