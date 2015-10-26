##! A framework for establishing and controlling a cluster of Bro instances.
##! In order to use the cluster framework, a script named
##! ``cluster-layout.bro`` must exist somewhere in Bro's script search path
##! which has a cluster definition of the :bro:id:`Cluster::nodes` variable.
##! The ``CLUSTER_NODE`` environment variable or :bro:id:`Cluster::node`
##! must also be sent and the cluster framework loaded as a package like
##! ``@load base/frameworks/cluster``.

@load base/frameworks/control

module Cluster;

export {
	## The cluster logging stream identifier.
	redef enum Log::ID += { LOG };

	## The record type which contains the column fields of the cluster log.
	type Info: record {
		## The time at which a cluster message was generated.
		ts:       time;
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
		## A node type responsible for log and policy management.
		MANAGER,
		## A node type for relaying worker node communication and synchronizing
		## worker node state.
		DATANODE,
		## The node type doing all the actual traffic analysis.
		WORKER,
		## A node acting as a traffic recorder using the
		## `Time Machine <http://bro.org/community/time-machine.html>`_
		## software.
		TIME_MACHINE,
	};
	
	## Events raised by a manager and handled by the workers.
	const manager2worker_events : set[string] = {} &redef;
	
	## Events raised by a manager and handled by proxies.
	const manager2datanode_events : set[string] = {} &redef;
	
	## Events raised by proxies and handled by a manager.
	const datanode2manager_events : set[string] = {} &redef;
	
	## Events raised by proxies and handled by workers.
	const datanode2worker_events : set[string] = {} &redef;
	
	## Events raised by workers and handled by a manager.
	const worker2manager_events : set[string] = {} &redef;
	
	## Events raised by workers and handled by proxies.
	const worker2datanode_events : set[string] = {} &redef;
	
	## Events raised by TimeMachine instances and handled by a manager.
	const tm2manager_events : set[string] = {} &redef;
	
	## Events raised by TimeMachine instances and handled by workers.
	const tm2worker_events : set[string] = {} &redef;
	
	## The prefix used for subscribing and publishing events
	const pub_sub_prefix : string = "bro/event/cluster/" &redef;

	## Record type to indicate a node in a cluster.
	type Node: record {
		## Identifies the type of cluster node in this node's configuration.
		node_type:    NodeType;
		## The IP address of the cluster node.
		ip:           addr;
		## If the *ip* field is a non-global IPv6 address, this field
		## can specify a particular :rfc:`4007` ``zone_id``.
		zone_id:      string      &default="";
		## The port to which this local node can connect when
		## establishing communication.
		p:            port;
		## Identifier for the interface a worker is sniffing.
		interface:    string      &optional;
		## Name of the manager node this node uses.  For workers and proxies.
		manager:      string      &optional;
		## Name of the datanode this node uses.  For workers and managers.
		datanode:     string      &optional;
		## Names of worker nodes that this node connects with.
		## For managers and proxies.
		workers:      set[string] &optional;
		## Name of a time machine node with which this node connects.
		time_machine: string      &optional;
	};
	
	## This function can be called at any time to determine if the cluster
	## framework is being enabled for this run.
	##
	## Returns: True if :bro:id:`Cluster::node` has been set.
	global is_enabled: function(): bool;
	
	## This function can be called at any time to determine what type of
	## cluster node the current Bro instance is going to be acting as.
	## If :bro:id:`Cluster::is_enabled` returns false, then
	## :bro:enum:`Cluster::NONE` is returned.
	##
	## Returns: The :bro:type:`Cluster::NodeType` the calling node acts as.
	global local_node_type: function(): NodeType;
	
	## Register events with broker that the local node will publish
	##
	## prefix: the broker pub-sub prefix
	## event_list: a list of events to be published via this prefix
	global register_broker_events: function(prefix: string, event_list: set[string]);

	## This gives the value for the number of workers currently connected to,
	## and it's maintained internally by the cluster framework.  It's 
	## primarily intended for use by managers to find out how many workers 
	## should be responding to requests.
	global worker_count: count = 0;
	
	## The cluster layout definition.  This should be placed into a filter
	## named cluster-layout.bro somewhere in the BROPATH.  It will be 
	## automatically loaded if the CLUSTER_NODE environment variable is set.
	## Note that BroControl handles all of this automatically.
	const nodes: table[string] of Node = {} &redef;
	
	## This is usually supplied on the command line for each instance
	## of the cluster that is started up.
	const node = getenv("CLUSTER_NODE") &redef;

	## The local datastore that can be either master or clone
	global cluster_store: opaque of Broker::Handle;

	# Set the correct name of this endpoint according to cluster-layout
	redef Broker::endpoint_name = node;
}

function is_enabled(): bool
	{
	return (node != "");
	}

function local_node_type(): NodeType
	{
	return is_enabled() ? nodes[node]$node_type : NONE;
	}

function register_broker_events(prefix: string, event_list: set[string])
	{
	for ( e in event_list )
		{
		local topic = string_cat(prefix, e);
		Broker::publish_topic(topic);
		Broker::auto_event(topic, lookup_ID(e));
		}
	}

event Broker::incoming_connection_established(peer_name: string) &priority=5
	{
	if ( peer_name in nodes && nodes[peer_name]$node_type == WORKER )
		++worker_count;
	}

event Broker::incoming_connection_broken(peer_name: string) &priority=5
	{
	if ( peer_name in nodes && nodes[peer_name]$node_type == WORKER )
		--worker_count;
	}

event bro_init() &priority=5
	{
	# If a node is given, but it's an unknown name we need to fail.
	if ( node != "" && node !in nodes )
		{
		Reporter::error(fmt("'%s' is not a valid node in the Cluster::nodes configuration", node));
		terminate();
		}

	Log::create_stream(Cluster::LOG, [$columns=Info, $path="cluster"]);
	}
