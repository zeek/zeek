:tocdepth: 3

base/protocols/websocket/main.zeek
==================================
.. zeek:namespace:: WebSocket

Implements base functionality for WebSocket analysis.

Upon a websocket_established() event, logs all gathered information into
websocket.log and configures the WebSocket analyzer with the headers
collected via http events.

:Namespace: WebSocket
:Imports: :doc:`base/protocols/http </scripts/base/protocols/http/index>`, :doc:`base/protocols/websocket/consts.zeek </scripts/base/protocols/websocket/consts.zeek>`

Summary
~~~~~~~
Types
#####
================================================= ======================================
:zeek:type:`WebSocket::Info`: :zeek:type:`record` The record type for the WebSocket log.
================================================= ======================================

Redefinitions
#############
========================================================================== ================================================================
:zeek:id:`HTTP::upgrade_analyzers`: :zeek:type:`table` :zeek:attr:`&redef`
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                                                           * :zeek:enum:`WebSocket::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                                                           :New Fields: :zeek:type:`connection`

                                                                             websocket: :zeek:type:`WebSocket::Info` :zeek:attr:`&optional`
========================================================================== ================================================================

Events
######
======================================================= =================================================================
:zeek:id:`WebSocket::log_websocket`: :zeek:type:`event` Event that can be handled to access the WebSocket record as it is
                                                        sent on to the logging framework.
======================================================= =================================================================

Hooks
#####
============================================================== =================================================================
:zeek:id:`WebSocket::configure_analyzer`: :zeek:type:`hook`    Experimental: Hook to intercept WebSocket analyzer configuration.
:zeek:id:`WebSocket::log_policy`: :zeek:type:`Log::PolicyHook` Log policy hook.
============================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: WebSocket::Info
   :source-code: base/protocols/websocket/main.zeek 22 47

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: host :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Same as in the HTTP log.


   .. zeek:field:: uri :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Same as in the HTTP log.


   .. zeek:field:: user_agent :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Same as in the HTTP log.


   .. zeek:field:: subprotocol :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The WebSocket subprotocol as selected by the server.


   .. zeek:field:: client_protocols :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The protocols requested by the client, if any.


   .. zeek:field:: server_extensions :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The extensions selected by the the server, if any.


   .. zeek:field:: client_extensions :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The extensions requested by the client, if any.


   .. zeek:field:: client_key :zeek:type:`string` :zeek:attr:`&optional`

      The Sec-WebSocket-Key header from the client.


   .. zeek:field:: server_accept :zeek:type:`string` :zeek:attr:`&optional`

      The Sec-WebSocket-Accept header from the server.


   The record type for the WebSocket log.

Events
######
.. zeek:id:: WebSocket::log_websocket
   :source-code: base/protocols/websocket/main.zeek 51 51

   :Type: :zeek:type:`event` (rec: :zeek:type:`WebSocket::Info`)

   Event that can be handled to access the WebSocket record as it is
   sent on to the logging framework.

Hooks
#####
.. zeek:id:: WebSocket::configure_analyzer
   :source-code: base/protocols/websocket/main.zeek 72 72

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`, aid: :zeek:type:`count`, config: :zeek:type:`WebSocket::AnalyzerConfig`) : :zeek:type:`bool`


   :param Experimental: Hook to intercept WebSocket analyzer configuration.

   Breaking from this hook disables the WebSocket analyzer immediately.
   To modify the configuration of the analyzer, use the
   :zeek:see:`WebSocket::AnalyzerConfig` type.

   While this API allows quite some flexibility currently, should be
   considered experimental and may change in the future with or
   without a deprecation phase.


   :param c: The connection


   :param aid: The analyzer ID for the WebSocket analyzer.


   :param config: The configuration record, also containing information
           about the subprotocol and extensions.

.. zeek:id:: WebSocket::log_policy
   :source-code: base/protocols/websocket/main.zeek 54 54

   :Type: :zeek:type:`Log::PolicyHook`

   Log policy hook.


