:tocdepth: 3

base/bif/plugins/Zeek_NCP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== ===================================================
:zeek:id:`ncp_reply`: :zeek:type:`event`   Generated for NCP replies (Netware Core Protocol).
:zeek:id:`ncp_request`: :zeek:type:`event` Generated for NCP requests (Netware Core Protocol).
========================================== ===================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: ncp_reply
   :source-code: base/bif/plugins/Zeek_NCP.events.bif.zeek 49 49

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, frame_type: :zeek:type:`count`, length: :zeek:type:`count`, req_frame: :zeek:type:`count`, req_func: :zeek:type:`count`, completion_code: :zeek:type:`count`)

   Generated for NCP replies (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :param c: The connection.
   

   :param frame_type: The frame type, as specified by the protocol.
   

   :param length: The length of the request body, excluding the frame header.
   

   :param req_frame: The frame type from the corresponding request.
   

   :param req_func: The function code from the corresponding request.
   

   :param completion_code: The reply's completion code, as specified by the protocol.
   
   .. zeek:see:: ncp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ncp_request
   :source-code: base/bif/plugins/Zeek_NCP.events.bif.zeek 23 23

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, frame_type: :zeek:type:`count`, length: :zeek:type:`count`, func: :zeek:type:`count`)

   Generated for NCP requests (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :param c: The connection.
   

   :param frame_type: The frame type, as specified by the protocol.
   

   :param length: The length of the request body, excluding the frame header.
   

   :param func: The requested function, as specified by the protocol.
   
   .. zeek:see:: ncp_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


