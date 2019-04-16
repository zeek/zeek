:tocdepth: 3

base/bif/plugins/Bro_NCP.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================== ===================================================
:bro:id:`ncp_reply`: :bro:type:`event`   Generated for NCP replies (Netware Core Protocol).
:bro:id:`ncp_request`: :bro:type:`event` Generated for NCP requests (Netware Core Protocol).
======================================== ===================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ncp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, frame_type: :bro:type:`count`, length: :bro:type:`count`, req_frame: :bro:type:`count`, req_func: :bro:type:`count`, completion_code: :bro:type:`count`)

   Generated for NCP replies (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :c: The connection.
   

   :frame_type: The frame type, as specified by the protocol.
   

   :length: The length of the request body, excluding the frame header.
   

   :req_frame: The frame type from the corresponding request.
   

   :req_func: The function code from the corresponding request.
   

   :completion_code: The reply's completion code, as specified by the protocol.
   
   .. bro:see:: ncp_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ncp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, frame_type: :bro:type:`count`, length: :bro:type:`count`, func: :bro:type:`count`)

   Generated for NCP requests (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :c: The connection.
   

   :frame_type: The frame type, as specified by the protocol.
   

   :length: The length of the request body, excluding the frame header.
   

   :func: The requested function, as specified by the protocol.
   
   .. bro:see:: ncp_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


