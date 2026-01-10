:tocdepth: 3

base/bif/plugins/Zeek_WebSocket.events.bif.zeek
===============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ==========================================================
:zeek:id:`websocket_close`: :zeek:type:`event`       Generated for WebSocket Close frames.
:zeek:id:`websocket_established`: :zeek:type:`event` Generated when a WebSocket handshake completed.
:zeek:id:`websocket_frame`: :zeek:type:`event`       Generated for every WebSocket frame.
:zeek:id:`websocket_frame_data`: :zeek:type:`event`  Generated for every chunk of WebSocket frame payload data.
:zeek:id:`websocket_message`: :zeek:type:`event`     Generated for every completed WebSocket message.
==================================================== ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: websocket_close
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 72 72

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, status: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for WebSocket Close frames.


   :param c: The WebSocket connection.


   :param is_orig: True if the frame is from the originator, else false.


   :param status: If the CloseFrame had no payload, this is 0, otherwise the value
           of the first two bytes in the frame's payload.


   :param reason: Remaining payload after *status*. This is capped at
           2 bytes less than :zeek:see:`WebSocket::payload_chunk_size`.

   .. zeek:see:: WebSocket::payload_chunk_size

.. zeek:id:: websocket_established
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 11 11

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, aid: :zeek:type:`count`)

   Generated when a WebSocket handshake completed.


   :param c: The WebSocket connection.


   :param aid: The analyzer identifier of the WebSocket analyzer.

   .. zeek:see:: WebSocket::__configure_analyzer WebSocket::configure_analyzer

.. zeek:id:: websocket_frame
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 28 28

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, fin: :zeek:type:`bool`, rsv: :zeek:type:`count`, opcode: :zeek:type:`count`, payload_len: :zeek:type:`count`)

   Generated for every WebSocket frame.


   :param c: The WebSocket connection.


   :param is_orig: True if the frame is from the originator, else false.


   :param fin: True if the fin bit is set, else false.


   :param rsv: The value of the RSV1, RSV2 and RSV3 bits.


   :param opcode: The frame's opcode.


   :param payload_len: The frame's payload length.


.. zeek:id:: websocket_frame_data
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for every chunk of WebSocket frame payload data.

   Do not use it to extract data from a WebSocket connection unless for testing
   or experimentation. Consider implementing a proper analyzer instead.


   :param c: The WebSocket connection.


   :param is_orig: True if the frame is from the originator, else false.


   :param data: One data chunk of frame payload. The length of is at most
         :zeek:see:`WebSocket::payload_chunk_size` bytes. A frame with
         a longer payload will result in multiple events events.

   .. zeek:see:: WebSocket::payload_chunk_size

.. zeek:id:: websocket_message
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, opcode: :zeek:type:`count`)

   Generated for every completed WebSocket message.


   :param c: The WebSocket connection.


   :param is_orig: True if the frame is from the originator, else false.


   :param opcode: The first frame's opcode.


