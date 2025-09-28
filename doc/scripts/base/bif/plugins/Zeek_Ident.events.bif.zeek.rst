:tocdepth: 3

base/bif/plugins/Zeek_Ident.events.bif.zeek
===========================================
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
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 67 67

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, line: :zeek:type:`string`)

   Generated for Ident error replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The corresponding request's local port.
   

   :param rport: The corresponding request's remote port.
   

   :param line: The error description returned by the reply.
   
   .. zeek:see:: ident_reply ident_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_reply
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, user_id: :zeek:type:`string`, system: :zeek:type:`string`)

   Generated for Ident replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The corresponding request's local port.
   

   :param rport: The corresponding request's remote port.
   

   :param user_id: The user id returned by the reply.
   

   :param system: The operating system returned by the reply.
   
   .. zeek:see:: ident_error  ident_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_request
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`)

   Generated for Ident requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The request's local port.
   

   :param rport: The request's remote port.
   
   .. zeek:see:: ident_error ident_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


