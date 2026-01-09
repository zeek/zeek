:orphan:

Package: base/protocols/websocket
=================================


:doc:`/scripts/base/protocols/websocket/__load__.zeek`


:doc:`/scripts/base/protocols/websocket/consts.zeek`

   WebSocket constants.

:doc:`/scripts/base/protocols/websocket/main.zeek`

   Implements base functionality for WebSocket analysis.

   Upon a websocket_established() event, logs all gathered information into
   websocket.log and configures the WebSocket analyzer with the headers
   collected via http events.

