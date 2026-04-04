:tocdepth: 3

base/protocols/websocket/consts.zeek
====================================
.. zeek:namespace:: WebSocket

WebSocket constants.

:Namespace: WebSocket

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================================================== =
:zeek:id:`WebSocket::opcodes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
=================================================================================================================== =

Constants
#########
============================================================= =
:zeek:id:`WebSocket::HANDSHAKE_GUID`: :zeek:type:`string`
:zeek:id:`WebSocket::OPCODE_BINARY`: :zeek:type:`count`
:zeek:id:`WebSocket::OPCODE_CLOSE`: :zeek:type:`count`
:zeek:id:`WebSocket::OPCODE_CONTINUATION`: :zeek:type:`count`
:zeek:id:`WebSocket::OPCODE_PING`: :zeek:type:`count`
:zeek:id:`WebSocket::OPCODE_PONG`: :zeek:type:`count`
:zeek:id:`WebSocket::OPCODE_TEXT`: :zeek:type:`count`
============================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: WebSocket::opcodes
   :source-code: base/protocols/websocket/consts.zeek 13 13

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [0] = "continuation",
            [9] = "ping",
            [10] = "pong",
            [2] = "binary",
            [8] = "close",
            [1] = "text"
         }



Constants
#########
.. zeek:id:: WebSocket::HANDSHAKE_GUID
   :source-code: base/protocols/websocket/consts.zeek 22 22

   :Type: :zeek:type:`string`
   :Default: ``"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"``


.. zeek:id:: WebSocket::OPCODE_BINARY
   :source-code: base/protocols/websocket/consts.zeek 8 8

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: WebSocket::OPCODE_CLOSE
   :source-code: base/protocols/websocket/consts.zeek 9 9

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: WebSocket::OPCODE_CONTINUATION
   :source-code: base/protocols/websocket/consts.zeek 6 6

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: WebSocket::OPCODE_PING
   :source-code: base/protocols/websocket/consts.zeek 10 10

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: WebSocket::OPCODE_PONG
   :source-code: base/protocols/websocket/consts.zeek 11 11

   :Type: :zeek:type:`count`
   :Default: ``10``


.. zeek:id:: WebSocket::OPCODE_TEXT
   :source-code: base/protocols/websocket/consts.zeek 7 7

   :Type: :zeek:type:`count`
   :Default: ``1``



