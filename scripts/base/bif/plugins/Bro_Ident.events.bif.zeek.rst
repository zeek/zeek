:tocdepth: 3

base/bif/plugins/Bro_Ident.events.bif.zeek
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== ==================================
:bro:id:`ident_error`: :bro:type:`event`   Generated for Ident error replies.
:bro:id:`ident_reply`: :bro:type:`event`   Generated for Ident replies.
:bro:id:`ident_request`: :bro:type:`event` Generated for Ident requests.
========================================== ==================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ident_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`, line: :bro:type:`string`)

   Generated for Ident error replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :line: The error description returned by the reply.
   
   .. bro:see:: ident_reply ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ident_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`, user_id: :bro:type:`string`, system: :bro:type:`string`)

   Generated for Ident replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :user_id: The user id returned by the reply.
   

   :system: The operating system returned by the reply.
   
   .. bro:see:: ident_error  ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ident_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`)

   Generated for Ident requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The request's local port.
   

   :rport: The request's remote port.
   
   .. bro:see:: ident_error ident_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


