:tocdepth: 3

base/bif/plugins/Zeek_WebSocket.functions.bif.zeek
==================================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: WebSocket


:Namespaces: GLOBAL, WebSocket

Summary
~~~~~~~
Functions
#########
================================================================= =================================
:zeek:id:`WebSocket::__configure_analyzer`: :zeek:type:`function` Configure the WebSocket analyzer.
================================================================= =================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: WebSocket::__configure_analyzer
   :source-code: base/bif/plugins/Zeek_WebSocket.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, aid: :zeek:type:`count`, config: :zeek:type:`WebSocket::AnalyzerConfig`) : :zeek:type:`bool`

   Configure the WebSocket analyzer.
   
   Called during :zeek:see:`websocket_established` to configure
   the WebSocket analyzer given the selected protocol and extension
   as chosen by the server.
   

   :param c: The WebSocket connection.

   :param aid: The identifier for the WebSocket analyzer as provided to :zeek:see:`websocket_established`.
   

   :param server_protocol: The protocol as found in the server's Sec-WebSocket-Protocol HTTP header, or empty.
   

   :param server_extensions: The extension as selected by the server via the Sec-WebSocket-Extensions HTTP Header.
   
   .. zeek:see:: websocket_established


