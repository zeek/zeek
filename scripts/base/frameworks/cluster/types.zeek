# Types used by the Cluster framework.
module Cluster;

export {
	## Types of nodes that are allowed to participate in the cluster
	## configuration.
	type NodeType: enum {
		## A dummy node type indicating the local node is not operating
		## within a cluster.
		NONE,
		## A node type which is allowed to view/manipulate the configuration
		## of other nodes in the cluster.
		CONTROL,
		## A node type responsible for log management.
		LOGGER,
		## A node type responsible for policy management.
		MANAGER,
		## A node type for relaying worker node communication and synchronizing
		## worker node state.
		PROXY,
		## The node type doing all the actual traffic analysis.
		WORKER,
	};

	## Record type to indicate a node in a cluster.
	type Node: record {
		## Identifies the type of cluster node in this node's configuration.
		node_type:    NodeType;
		## The IP address of the cluster node.
		ip:           addr;
		## If the *ip* field is a non-global IPv6 address, this field
		## can specify a particular :rfc:`4007` ``zone_id``.
		zone_id:      string      &default="";
		## The port that this node will listen on for peer connections.
		## A value of ``0/unknown`` means the node is not pre-configured to listen.
		p:            port        &default=0/unknown;
		## Name of the manager node this node uses.  For workers and proxies.
		manager:      string      &optional;
		## A unique identifier assigned to the node by the broker framework.
		## This field is only set while a node is connected.
		id: string                &optional;
		## The port used to expose metrics to Prometheus. Setting this in a cluster
		## configuration will override the setting for Telemetry::metrics_port for
		## the node.
		metrics_port: port        &optional;
	};

	## Record to represent a cluster node including its name.
	type NamedNode: record {
		name: string;
		node: Node;
	};

	## An event instance for cluster pub/sub.
	##
	## See :zeek:see:`Cluster::publish` and :zeek:see:`Cluster::make_event`.
	type Event: record {
		## The event handler to be invoked on the remote node.
		ev: any;
		## The arguments for the event.
		args: vector of any;
	};

	## The default maximum queue size for WebSocket event dispatcher instances.
	##
	## If the maximum queue size is reached, events from external WebSocket
	## clients will be stalled and processed once the queue has been drained.
	##
	## An internal metric named ``cluster_onloop_queue_stalls`` and
	## labeled with a ``WebSocketEventDispatcher:<host>:<port>`` tag
	## is incremented when the maximum queue size is reached.
	const default_websocket_max_event_queue_size = 32 &redef;

	## The default ping interval for WebSocket clients.
	const default_websocket_ping_interval = 5 sec &redef;

	## The TLS options for a WebSocket server.
	##
	## If cert_file and key_file are set, TLS is enabled. If both
	## are unset, TLS is disabled. Any other combination is an error.
	type WebSocketTLSOptions: record {
		## The cert file to use.
		cert_file: string &optional;
		## The key file to use.
		key_file: string &optional;
		## Expect peers to send client certificates.
		enable_peer_verification: bool &default=F;
		## The CA certificate or CA bundle used for peer verification.
		## Empty will use the implementations's default when
		## ``enable_peer_verification`` is T.
		ca_file: string &default="";
		## The ciphers to use. Empty will use the implementation's defaults.
		ciphers: string &default="";
	};

	## WebSocket server options to pass to :zeek:see:`Cluster::listen_websocket`.
	type WebSocketServerOptions: record {
		## The address to listen on, cannot be used together with ``listen_host``.
		listen_addr: addr &optional;
		## The port the WebSocket server is supposed to listen on.
		listen_port: port;
		## The maximum event queue size for this server.
		max_event_queue_size: count &default=default_websocket_max_event_queue_size;
		## Ping interval to use. A WebSocket client not responding to
		## the pings will be disconnected. Set to a negative value to
		## disable pings. Subsecond intervals are currently not supported.
		ping_interval: interval &default=default_websocket_ping_interval;
		## The TLS options used for this WebSocket server. By default,
		## TLS is disabled. See also :zeek:see:`Cluster::WebSocketTLSOptions`.
		tls_options: WebSocketTLSOptions &default=WebSocketTLSOptions();
	};

	## Network information of an endpoint.
	type NetworkInfo: record {
		## The IP address or hostname where the endpoint listens.
		address: string;
		## The port where the endpoint is bound to.
		bound_port: port;
	};

	## Information about a WebSocket endpoint.
	type EndpointInfo: record {
		id: string;
		network: NetworkInfo;
		## The value of the X-Application-Name HTTP header, if any.
		application_name: string &optional;
	};
}
