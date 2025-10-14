:tocdepth: 3

base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek
=======================================================
.. zeek:namespace:: Cluster
.. zeek:namespace:: GLOBAL


:Namespaces: Cluster, GLOBAL

Summary
~~~~~~~
Events
######
============================================================== ====================================================
:zeek:id:`Cluster::websocket_client_added`: :zeek:type:`event` Generated when a new WebSocket client has connected.
:zeek:id:`Cluster::websocket_client_lost`: :zeek:type:`event`  Generated when a WebSocket client was lost.
============================================================== ====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Cluster::websocket_client_added
   :source-code: base/frameworks/cluster/main.zeek 702 707

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Cluster::EndpointInfo`, subscriptions: :zeek:type:`string_vec`)

   Generated when a new WebSocket client has connected.
   

   :param endpoint: Various information about the WebSocket client.
   

   :param subscriptions: The WebSocket client's subscriptions as provided in the handshake.

.. zeek:id:: Cluster::websocket_client_lost
   :source-code: base/frameworks/cluster/main.zeek 709 715

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Cluster::EndpointInfo`, code: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated when a WebSocket client was lost.
   

   :param endpoint: Various information about the WebSocket client.

   :param code: The code sent by the client in its CLOSE frame, or a code generated
         internally if the server disconnected the client.

   :param reason: The reason sent by the client in its CLOSE frame, or a reason generated
           internally if the server disconnected the client.


