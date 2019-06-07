:tocdepth: 3

base/bif/plugins/Bro_Finger.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ==============================
:zeek:id:`finger_reply`: :zeek:type:`event`   Generated for Finger replies.
:zeek:id:`finger_request`: :zeek:type:`event` Generated for Finger requests.
============================================= ==============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: finger_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, reply_line: :zeek:type:`string`)

   Generated for Finger replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :reply_line: The reply as returned by the server
   
   .. zeek:see:: finger_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: finger_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, full: :zeek:type:`bool`, username: :zeek:type:`string`, hostname: :zeek:type:`string`)

   Generated for Finger requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :full: True if verbose information is requested (``/W`` switch).
   

   :username: The request's user name.
   

   :hostname: The request's host name.
   
   .. zeek:see:: finger_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


