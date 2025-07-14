##! A framework for establishing and controlling a cluster of Zeek instances.
##! In order to use the cluster framework, a script named
##! ``cluster-layout.zeek`` must exist somewhere in Zeek's script search path
##! which has a cluster definition of the :zeek:id:`Cluster::nodes` variable.
##! The ``CLUSTER_NODE`` environment variable or :zeek:id:`Cluster::node`
##! must also be sent and the cluster framework loaded as a package like
##! ``@load base/frameworks/cluster``.
##!
##! .. warning::
##!
##!     The file ``cluster-layout.zeek`` should only contain the definition
##!     of :zeek:id:`Cluster::nodes`. Specifically, avoid loading other Zeek
##!     scripts or using :zeek:see:`redef` for anything but :zeek:id:`Cluster::nodes`.
##!
##!     Due to ``cluster-layout.zeek`` being loaded very early, it is easy to
##!     introduce circular loading issues.

@load base/frameworks/control
@load base/frameworks/broker

module Cluster;

export {
	## Whether to distribute log messages among available logging nodes.
	const enable_round_robin_logging = T &redef;

	## The topic name used for exchanging messages that are relevant to
	## logger nodes in a cluster.  Used with broker-enabled cluster communication.
	const logger_topic = "zeek/cluster/logger" &redef;

	## The topic name used for exchanging messages that are relevant to
	## manager nodes in a cluster.  Used with broker-enabled cluster communication.
	const manager_topic = "zeek/cluster/manager" &redef;

	## The topic name used for exchanging messages that are relevant to
	## proxy nodes in a cluster.  Used with broker-enabled cluster communication.
	const proxy_topic = "zeek/cluster/proxy" &redef;

	## The topic name used for exchanging messages that are relevant to
	## worker nodes in a cluster.  Used with broker-enabled cluster communication.
	const worker_topic = "zeek/cluster/worker" &redef;

	## A set of topic names to be used for broadcasting messages that are
	## relevant to all nodes in a cluster. Currently, there is not a common
	## topic to broadcast to, because enabling implicit Broker forwarding would
	## cause a routing loop for this topic.
	const broadcast_topics = {
		logger_topic,
		manager_topic,
		proxy_topic,
		worker_topic,
	};

	## The topic prefix used for exchanging messages that are relevant to
	## a named node in a cluster.  Used with broker-enabled cluster communication.
	const node_topic_prefix = "zeek/cluster/node/" &redef;

	## The topic prefix used for exchanging messages that are relevant to
	## a unique node in a cluster.  Used with broker-enabled cluster communication.
	const nodeid_topic_prefix = "zeek/cluster/nodeid/" &redef;

	## Name of the node on which master data stores will be created if no other
	## has already been specified by the user in :zeek:see:`Cluster::stores`.
	## An empty value means "use whatever name corresponds to the manager
	## node".
	const default_master_node = "" &redef;

	## The type of data store backend that will be used for all data stores if
	## no other has already been specified by the user in :zeek:see:`Cluster::stores`.
	const default_backend = Broker::MEMORY &redef;

	## The type of persistent data store backend that will be used for all data
	## stores if no other has already been specified by the user in
	## :zeek:see:`Cluster::stores`.  This will be used when script authors call
	## :zeek:see:`Cluster::create_store` with the *persistent* argument set true.
	const default_persistent_backend = Broker::SQLITE &redef;

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

	## Setting a default dir will, for persistent backends that have not
	## been given an explicit file path via :zeek:see:`Cluster::stores`,
	## automatically create a path within this dir that is based on the name of
	## the data store.
	const default_store_dir = "" &redef;

	## Information regarding a cluster-enabled data store.
	type StoreInfo: record {
		## The name of the data store.
		name: string &optional;
		## The store handle.
		store: opaque of Broker::Store &optional;
		## The name of the cluster node on which the master version of the data
		## store resides.
		master_node: string &default=default_master_node;
		## Whether the data store is the master version or a clone.
		master: bool &default=F;
		## The type of backend used for storing data.
		backend: Broker::BackendType &default=default_backend;
		## Parameters used for configuring the backend.
		options: Broker::BackendOptions &default=Broker::BackendOptions();
		## A resync/reconnect interval to pass through to
		## :zeek:see:`Broker::create_clone`.
		clone_resync_interval: interval &default=Broker::default_clone_resync_interval;
		## A staleness duration to pass through to
		## :zeek:see:`Broker::create_clone`.
		clone_stale_interval: interval &default=Broker::default_clone_stale_interval;
		## A mutation buffer interval to pass through to
		## :zeek:see:`Broker::create_clone`.
		clone_mutation_buffer_interval: interval &default=Broker::default_clone_mutation_buffer_interval;
	};

	## A table of cluster-enabled data stores that have been created, indexed
	## by their name.  This table will be populated automatically by
	## :zeek:see:`Cluster::create_store`, but if you need to customize
	## the options related to a particular data store, you may redef this
	## table.  Calls to :zeek:see:`Cluster::create_store` will first check
	## the table for an entry of the same name and, if found, will use the
	## predefined options there when setting up the store.
	global stores: table[string] of StoreInfo &default=StoreInfo() &redef;

	## Sets up a cluster-enabled data store.  They will also still properly
	## function for uses that are not operating a cluster.
	##
	## name: the name of the data store to create.
	##
	## persistent: whether the data store must be persistent.
	##
	## Returns: the store's information.  For master stores, the store will be
	##          ready to use immediately.  For clones, the store field will not
	##          be set until the node containing the master store has connected.
	global create_store: function(name: string, persistent: bool &default=F): StoreInfo;

	## The cluster logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the cluster log.
	type Info: record {
		## The time at which a cluster message was generated.
		ts:       time;
		## The name of the node that is creating the log record.
		node: string;
		## A message indicating information about the cluster's operation.
		message:  string;
	} &log;

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

	## This function can be called at any time to determine if the cluster
	## framework is being enabled for this run.
	##
	## Returns: True if :zeek:id:`Cluster::node` has been set.
	global is_enabled: function(): bool;

	## This function can be called at any time to determine what type of
	## cluster node the current Zeek instance is going to be acting as.
	## If :zeek:id:`Cluster::is_enabled` returns false, then
	## :zeek:enum:`Cluster::NONE` is returned.
	##
	## Returns: The :zeek:type:`Cluster::NodeType` the calling node acts as.
	global local_node_type: function(): NodeType;

	## This function can be called at any time to determine the configured
	## metrics port for Prometheus being used by current Zeek instance. If
	## :zeek:id:`Cluster::is_enabled` returns false or the node isn't found,
	## ``0/unknown`` is returned.
	##
	## Returns: The metrics port used by the calling node.
	global local_node_metrics_port: function(): port;

	## The cluster layout definition.  This should be placed into a filter
	## named cluster-layout.zeek somewhere in the ZEEKPATH.  It will be
	## automatically loaded if the CLUSTER_NODE environment variable is set.
	## Note that ZeekControl handles all of this automatically.
	## The table is typically indexed by node names/labels (e.g. "manager"
	## or "worker-1").
	const nodes: table[string] of Node = {} &redef;

	## Returns the number of nodes defined in the cluster layout for a given
	## node type.
	global get_node_count: function(node_type: NodeType): count;

	## Returns the number of nodes per type, the calling node is currently
	## connected to. This is primarily intended for use by the manager to find
	## out how many nodes should be responding to requests.
	global get_active_node_count: function(node_type: NodeType): count;

	## Indicates whether or not the manager will act as the logger and receive
	## logs.  This value should be set in the cluster-layout.zeek script (the
	## value should be true only if no logger is specified in Cluster::nodes).
	## Note that ZeekControl handles this automatically.
	const manager_is_logger = T &redef;

	## This is usually supplied on the command line for each instance
	## of the cluster that is started up.
	const node = getenv("CLUSTER_NODE") &redef;

	## Function returning this node's identifier.
	##
	## By default this is :zeek:see:`Broker::node_id`, but can be
	## redefined by other cluster backends. This identifier should be
	## a short lived identifier that resets when a node is restarted.
	global node_id: function(): string = Broker::node_id &redef;

	## Interval for retrying failed connections between cluster nodes.
	## If set, the ZEEK_DEFAULT_CONNECT_RETRY (given in number of seconds)
	## environment variable overrides this option.
	const retry_interval = 1sec &redef;

	## When using broker-enabled cluster framework, nodes broadcast this event
	## to exchange their user-defined name along with a string that uniquely
	## identifies it for the duration of its lifetime.  This string may change
	## if the node dies and has to reconnect later.
	global hello: event(name: string, id: string);

	## When using broker-enabled cluster framework, this event will be emitted
	## locally whenever a cluster node connects or reconnects.
	global node_up: event(name: string, id: string);

	## When using broker-enabled cluster framework, this event will be emitted
	## locally whenever a connected cluster node becomes disconnected.
	global node_down: event(name: string, id: string);

	## Write a message to the cluster logging stream.
	global log: function(msg: string);

	## Retrieve the topic associated with a specific node in the cluster.
	##
	## name: the name of the cluster node (e.g. "manager").
	##
	## Returns: a topic string that may used to send a message exclusively to
	##          a given cluster node.
	global node_topic: function(name: string): string &redef;

	## Retrieve the topic associated with a specific node in the cluster.
	##
	## id: the id of the cluster node (from :zeek:see:`Broker::EndpointInfo`
	##     or :zeek:see:`Broker::node_id`.
	##
	## Returns: a topic string that may used to send a message exclusively to
	##          a given cluster node.
	global nodeid_topic: function(id: string): string &redef;

	## Retrieve the cluster-level naming of a node based on its node ID,
	## a backend-specific identifier.
	##
	## id: the node ID of a peer.
	##
	## Returns: the :zeek:see:`Cluster::NamedNode` for the requested node, if
	##          known, otherwise a "null" instance with an empty name field.
	global nodeid_to_node: function(id: string): NamedNode;

	## Initialize the cluster backend.
	##
	## Cluster backends usually invoke this from a :zeek:see:`zeek_init` handler.
	##
	## Returns: T on success, else F.
	global init: function(): bool;

	## Subscribe to the given topic.
	##
	## topic: The topic to subscribe to.
	##
	## Returns: T on success, else F.
	global subscribe: function(topic: string): bool;

	## Unsubscribe from the given topic.
	##
	## topic: The topic to unsubscribe from.
	##
	## Returns: T on success, else F.
	global unsubscribe: function(topic: string): bool;

	## An event instance for cluster pub/sub.
	##
	## See :zeek:see:`Cluster::publish` and :zeek:see:`Cluster::make_event`.
	type Event: record {
		## The event handler to be invoked on the remote node.
		ev: any;
		## The arguments for the event.
		args: vector of any;
	};

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
		## The host address to listen on.
		listen_host: string &optional &deprecated="Remove in v8.1: Use $listen_addr instead.";
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

	## Start listening on a WebSocket address.
	##
	## options: The server :zeek:see:`Cluster::WebSocketServerOptions` to use.
	##
	## Returns: T on success, else F.
	global listen_websocket: function(options: WebSocketServerOptions): bool;

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
	};
}

# Needs declaration of Cluster::Event type.
@load base/bif/cluster.bif
@load base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek

# Track active nodes per type.
global active_node_ids: table[NodeType] of set[string];

function nodes_with_type(node_type: NodeType): vector of NamedNode
	{
	local rval: vector of NamedNode = vector();

	for ( name, n in Cluster::nodes )
		{
		if ( n$node_type != node_type )
			next;

		rval += NamedNode($name=name, $node=n);
		}

	return sort(rval, function(n1: NamedNode, n2: NamedNode): int
		{ return strcmp(n1$name, n2$name); });
	}

function get_node_count(node_type: NodeType): count
	{
	local cnt = 0;

	for ( _, n in nodes )
		{
		if ( n$node_type == node_type )
			++cnt;
		}

	return cnt;
	}

function get_active_node_count(node_type: NodeType): count
	{
	return node_type in active_node_ids ? |active_node_ids[node_type]| : 0;
	}

function is_enabled(): bool
	{
	return (node != "");
	}

function local_node_type(): NodeType
	{
	if ( ! is_enabled() )
		return NONE;

	if ( node !in nodes )
		return NONE;

	return nodes[node]$node_type;
	}

function local_node_metrics_port(): port
	{
	if ( ! is_enabled() )
		return 0/unknown;

	if ( node !in nodes )
		return 0/unknown;

	if ( ! nodes[node]?$metrics_port )
		return 0/unknown;

	return nodes[node]$metrics_port;
	}

function node_topic(name: string): string
	{
	return node_topic_prefix + name + "/";
	}

function nodeid_topic(id: string): string
	{
	return nodeid_topic_prefix + id + "/";
	}

function nodeid_to_node(id: string): NamedNode
	{
	for ( name, n in nodes )
		{
		if ( n?$id && n$id == id )
			return NamedNode($name=name, $node=n);
		}

	return NamedNode($name="", $node=[$node_type=NONE, $ip=0.0.0.0]);
	}

event Cluster::hello(name: string, id: string) &priority=10
	{
	if ( name !in nodes )
		{
		Reporter::error(fmt("Got Cluster::hello msg from unexpected node: %s", name));
		return;
		}

	local n = nodes[name];

	if ( n?$id )
		{
		if ( n$id != id )
			Reporter::error(fmt("Got Cluster::hello msg from duplicate node:%s",
								name));
		}
	else
		event Cluster::node_up(name, id);

	n$id = id;
	Cluster::log(fmt("got hello from %s (%s)", name, id));

	if ( n$node_type !in active_node_ids )
		active_node_ids[n$node_type] = set();
	add active_node_ids[n$node_type][id];
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	if ( ! Cluster::is_enabled() )
		return;

	local e = Broker::make_event(Cluster::hello, node, Cluster::node_id());
	Broker::publish(nodeid_topic(endpoint$id), e);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == endpoint$id )
			{
			event Cluster::node_down(node_name, endpoint$id);
			break;
			}
		}
	}

event node_down(name: string, id: string) &priority=10
	{
	local found = F;
	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == id )
			{
			Cluster::log(fmt("node down: %s", node_name));
			delete n$id;
			delete active_node_ids[n$node_type][id];
			found = T;
			break;
			}
		}

	if ( ! found )
		Reporter::error(fmt("No node found in Cluster::node_down() node:%s id:%s",
		                    name, id));
	}

event zeek_init() &priority=5
	{
	# If a node is given, but it's an unknown name we need to fail.
	if ( node != "" && node !in nodes )
		{
		Reporter::error(fmt("'%s' is not a valid node in the Cluster::nodes configuration", node));
		terminate();
		}

	Log::create_stream(Cluster::LOG, [$columns=Info, $path="cluster", $policy=log_policy]);
	}

function create_store(name: string, persistent: bool &default=F): Cluster::StoreInfo
	{
	local info = stores[name];
	info$name = name;

	if ( Cluster::default_store_dir != "" )
		{
		local default_options = Broker::BackendOptions();
		local path = Cluster::default_store_dir + "/" + name;

		if ( info$options$sqlite$path == default_options$sqlite$path )
			info$options$sqlite$path = path + ".sqlite";
		}

	if ( persistent )
		{
		switch ( info$backend ) {
		case Broker::MEMORY:
			info$backend = Cluster::default_persistent_backend;
			break;
		case Broker::SQLITE:
			# no-op: user already asked for a specific persistent backend.
			break;
		default:
			Reporter::error(fmt("unhandled data store type: %s", info$backend));
			break;
		}
		}

	if ( ! Cluster::is_enabled() )
		{
		if ( info?$store )
			{
			Reporter::warning(fmt("duplicate cluster store creation for %s", name));
			return info;
			}

		info$store = Broker::create_master(name, info$backend, info$options);
		info$master = T;
		stores[name] = info;
		return info;
		}

	if ( info$master_node == "" )
		{
		local mgr_nodes = nodes_with_type(Cluster::MANAGER);

		if ( |mgr_nodes| == 0 )
			Reporter::fatal(fmt("empty master node name for cluster store " +
								"'%s', but there's no manager node to default",
			                    name));

		info$master_node = mgr_nodes[0]$name;
		}
	else if ( info$master_node !in Cluster::nodes )
		Reporter::fatal(fmt("master node '%s' for cluster store '%s' does not exist",
		                    info$master_node, name));

	if ( Cluster::node == info$master_node )
		{
		info$store = Broker::create_master(name, info$backend, info$options);
		info$master = T;
		stores[name] = info;
		Cluster::log(fmt("created master store: %s", name));
		return info;
		}

	info$master = F;
	stores[name] = info;
	info$store = Broker::create_clone(info$name,
	                                  info$clone_resync_interval,
	                                  info$clone_stale_interval,
	                                  info$clone_mutation_buffer_interval);
	Cluster::log(fmt("created clone store: %s", info$name));
	return info;
	}

function log(msg: string)
	{
	Log::write(Cluster::LOG, [$ts = network_time(), $node = node, $message = msg]);
	}

function init(): bool
	{
	return Cluster::Backend::__init(Cluster::node_id());
	}

function subscribe(topic: string): bool
	{
	return Cluster::__subscribe(topic);
	}

function unsubscribe(topic: string): bool
	{
	return Cluster::__unsubscribe(topic);
	}

function listen_websocket(options: WebSocketServerOptions): bool
	{
	return Cluster::__listen_websocket(options);
	}

event websocket_client_added(endpoint: EndpointInfo, subscriptions: string_vec)
	{
	local msg = fmt("WebSocket client '%s' (%s:%d) subscribed to %s",
	                endpoint$id, endpoint$network$address, endpoint$network$bound_port, subscriptions);
	Cluster::log(msg);
	}

event websocket_client_lost(endpoint: EndpointInfo, code: count, reason: string)
	{
	local msg = fmt("WebSocket client '%s' (%s:%d) gone with code %d%s",
	                endpoint$id, endpoint$network$address, endpoint$network$bound_port, code,
	                |reason| > 0 ? fmt(" and reason '%s'", reason) : "");
	Cluster::log(msg);
	}

# If a backend reports an error, propagate it via a reporter error message.
event Cluster::Backend::error(tag: string, message: string)
	{
	local msg = fmt("Cluster::Backend::error: %s (%s)", tag, message);
	Reporter::error(msg);
	}
