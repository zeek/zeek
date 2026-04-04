:tocdepth: 3

base/frameworks/cluster/types.zeek
==================================
.. zeek:namespace:: Cluster


:Namespace: Cluster

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================== ========================================================================
:zeek:id:`Cluster::default_websocket_max_event_queue_size`: :zeek:type:`count` :zeek:attr:`&redef` The default maximum queue size for WebSocket event dispatcher instances.
:zeek:id:`Cluster::default_websocket_ping_interval`: :zeek:type:`interval` :zeek:attr:`&redef`     The default ping interval for WebSocket clients.
================================================================================================== ========================================================================

Types
#####
================================================================= ==========================================================================
:zeek:type:`Cluster::EndpointInfo`: :zeek:type:`record`           Information about a WebSocket endpoint.
:zeek:type:`Cluster::Event`: :zeek:type:`record`                  An event instance for cluster pub/sub.
:zeek:type:`Cluster::NamedNode`: :zeek:type:`record`              Record to represent a cluster node including its name.
:zeek:type:`Cluster::NetworkInfo`: :zeek:type:`record`            Network information of an endpoint.
:zeek:type:`Cluster::Node`: :zeek:type:`record`                   Record type to indicate a node in a cluster.
:zeek:type:`Cluster::NodeType`: :zeek:type:`enum`                 Types of nodes that are allowed to participate in the cluster
                                                                  configuration.
:zeek:type:`Cluster::WebSocketServerOptions`: :zeek:type:`record` WebSocket server options to pass to :zeek:see:`Cluster::listen_websocket`.
:zeek:type:`Cluster::WebSocketTLSOptions`: :zeek:type:`record`    The TLS options for a WebSocket server.
================================================================= ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::default_websocket_max_event_queue_size
   :source-code: base/frameworks/cluster/types.zeek 72 72

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``32``

   The default maximum queue size for WebSocket event dispatcher instances.

   If the maximum queue size is reached, events from external WebSocket
   clients will be stalled and processed once the queue has been drained.

   An internal metric named ``cluster_onloop_queue_stalls`` and
   labeled with a ``WebSocketEventDispatcher:<host>:<port>`` tag
   is incremented when the maximum queue size is reached.

.. zeek:id:: Cluster::default_websocket_ping_interval
   :source-code: base/frameworks/cluster/types.zeek 75 75

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 secs``

   The default ping interval for WebSocket clients.

Types
#####
.. zeek:type:: Cluster::EndpointInfo
   :source-code: base/frameworks/cluster/types.zeek 122 127

   :Type: :zeek:type:`record`


   .. zeek:field:: id :zeek:type:`string`


   .. zeek:field:: network :zeek:type:`Cluster::NetworkInfo`


   .. zeek:field:: application_name :zeek:type:`string` :zeek:attr:`&optional`

      The value of the X-Application-Name HTTP header, if any.


   Information about a WebSocket endpoint.

.. zeek:type:: Cluster::Event
   :source-code: base/frameworks/cluster/types.zeek 57 62

   :Type: :zeek:type:`record`


   .. zeek:field:: ev :zeek:type:`any`

      The event handler to be invoked on the remote node.


   .. zeek:field:: args :zeek:type:`vector` of :zeek:type:`any`

      The arguments for the event.


   An event instance for cluster pub/sub.

   See :zeek:see:`Cluster::publish` and :zeek:see:`Cluster::make_event`.

.. zeek:type:: Cluster::NamedNode
   :source-code: base/frameworks/cluster/types.zeek 49 52

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`


   .. zeek:field:: node :zeek:type:`Cluster::Node`


   Record to represent a cluster node including its name.

.. zeek:type:: Cluster::NetworkInfo
   :source-code: base/frameworks/cluster/types.zeek 114 119

   :Type: :zeek:type:`record`


   .. zeek:field:: address :zeek:type:`string`

      The IP address or hostname where the endpoint listens.


   .. zeek:field:: bound_port :zeek:type:`port`

      The port where the endpoint is bound to.


   Network information of an endpoint.

.. zeek:type:: Cluster::Node
   :source-code: base/frameworks/cluster/types.zeek 26 46

   :Type: :zeek:type:`record`


   .. zeek:field:: node_type :zeek:type:`Cluster::NodeType`

      Identifies the type of cluster node in this node's configuration.


   .. zeek:field:: ip :zeek:type:`addr`

      The IP address of the cluster node.


   .. zeek:field:: zone_id :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      If the *ip* field is a non-global IPv6 address, this field
      can specify a particular :rfc:`4007` ``zone_id``.


   .. zeek:field:: p :zeek:type:`port` :zeek:attr:`&default` = ``0/unknown`` :zeek:attr:`&optional`

      The port that this node will listen on for peer connections.
      A value of ``0/unknown`` means the node is not pre-configured to listen.


   .. zeek:field:: manager :zeek:type:`string` :zeek:attr:`&optional`

      Name of the manager node this node uses.  For workers and proxies.


   .. zeek:field:: id :zeek:type:`string` :zeek:attr:`&optional`

      A unique identifier assigned to the node by the broker framework.
      This field is only set while a node is connected.


   .. zeek:field:: metrics_port :zeek:type:`port` :zeek:attr:`&optional`

      The port used to expose metrics to Prometheus. Setting this in a cluster
      configuration will override the setting for Telemetry::metrics_port for
      the node.


   Record type to indicate a node in a cluster.

.. zeek:type:: Cluster::NodeType
   :source-code: base/frameworks/cluster/types.zeek 7 24

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Cluster::NONE Cluster::NodeType

         A dummy node type indicating the local node is not operating
         within a cluster.

      .. zeek:enum:: Cluster::CONTROL Cluster::NodeType

         A node type which is allowed to view/manipulate the configuration
         of other nodes in the cluster.

      .. zeek:enum:: Cluster::LOGGER Cluster::NodeType

         A node type responsible for log management.

      .. zeek:enum:: Cluster::MANAGER Cluster::NodeType

         A node type responsible for policy management.

      .. zeek:enum:: Cluster::PROXY Cluster::NodeType

         A node type for relaying worker node communication and synchronizing
         worker node state.

      .. zeek:enum:: Cluster::WORKER Cluster::NodeType

         The node type doing all the actual traffic analysis.

   Types of nodes that are allowed to participate in the cluster
   configuration.

.. zeek:type:: Cluster::WebSocketServerOptions
   :source-code: base/frameworks/cluster/types.zeek 97 111

   :Type: :zeek:type:`record`


   .. zeek:field:: listen_addr :zeek:type:`addr` :zeek:attr:`&optional`

      The address to listen on, cannot be used together with ``listen_host``.


   .. zeek:field:: listen_port :zeek:type:`port`

      The port the WebSocket server is supposed to listen on.


   .. zeek:field:: max_event_queue_size :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`Cluster::default_websocket_max_event_queue_size` :zeek:attr:`&optional`

      The maximum event queue size for this server.


   .. zeek:field:: ping_interval :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Cluster::default_websocket_ping_interval` :zeek:attr:`&optional`

      Ping interval to use. A WebSocket client not responding to
      the pings will be disconnected. Set to a negative value to
      disable pings. Subsecond intervals are currently not supported.


   .. zeek:field:: tls_options :zeek:type:`Cluster::WebSocketTLSOptions` :zeek:attr:`&default` = *...* :zeek:attr:`&optional`

      The TLS options used for this WebSocket server. By default,
      TLS is disabled. See also :zeek:see:`Cluster::WebSocketTLSOptions`.


   WebSocket server options to pass to :zeek:see:`Cluster::listen_websocket`.

.. zeek:type:: Cluster::WebSocketTLSOptions
   :source-code: base/frameworks/cluster/types.zeek 81 94

   :Type: :zeek:type:`record`


   .. zeek:field:: cert_file :zeek:type:`string` :zeek:attr:`&optional`

      The cert file to use.


   .. zeek:field:: key_file :zeek:type:`string` :zeek:attr:`&optional`

      The key file to use.


   .. zeek:field:: enable_peer_verification :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Expect peers to send client certificates.


   .. zeek:field:: ca_file :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      The CA certificate or CA bundle used for peer verification.
      Empty will use the implementations's default when
      ``enable_peer_verification`` is T.


   .. zeek:field:: ciphers :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      The ciphers to use. Empty will use the implementation's defaults.


   The TLS options for a WebSocket server.

   If cert_file and key_file are set, TLS is enabled. If both
   are unset, TLS is disabled. Any other combination is an error.


