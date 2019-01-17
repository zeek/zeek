:tocdepth: 3

base/bif/plugins/Bro_Finger.events.bif.bro
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================== ==============================
:bro:id:`finger_reply`: :bro:type:`event`   Generated for Finger replies.
:bro:id:`finger_request`: :bro:type:`event` Generated for Finger requests.
=========================================== ==============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: finger_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, reply_line: :bro:type:`string`)

   Generated for Finger replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :reply_line: The reply as returned by the server
   
   .. bro:see:: finger_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: finger_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, full: :bro:type:`bool`, username: :bro:type:`string`, hostname: :bro:type:`string`)

   Generated for Finger requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :full: True if verbose information is requested (``/W`` switch).
   

   :username: The request's user name.
   

   :hostname: The request's host name.
   
   .. bro:see:: finger_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


