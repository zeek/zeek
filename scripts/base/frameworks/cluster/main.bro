@load base/frameworks/control/main

module Cluster;

export {
	redef enum Log::ID += { CLUSTER };
	type Info: record {
		ts:       time;
		message:  string;
	} &log;
	
	type NodeType: enum {
		NONE,
		CONTROL,
		MANAGER,
		PROXY,
		WORKER,
		TIME_MACHINE,
	};
	
	## Events raised by the manager and handled by the workers.
	const manager_events = /Drop::.*/ &redef;
	
	## Events raised by the proxies and handled by the manager.
	const proxy_events = /Notice::notice/ &redef;
	
	## Events raised by workers and handled by the manager.
	const worker_events = /(Notice::notice|TimeMachine::command|Drop::.*)/ &redef;
	
	## Events sent by the control host (i.e. BroControl) when dynamically 
	## connecting to a running instance to update settings or request data.
	const control_events = Control::controller_events &redef;
	
	## Record type to indicate a node in a cluster.
	type Node: record {
		node_type:    NodeType;
		ip:           addr;
		p:            port;
		
		## Identifier for the interface a worker is sniffing.
		interface:    string      &optional;
		
		## Manager node this node uses.  For workers and proxies.
		manager:      string      &optional;
		## Proxy node this node uses.  For workers and managers.
		proxy:        string      &optional;
		## Worker nodes that this node connects with.  For managers and proxies.
		workers:      set[string] &optional;
		time_machine: string      &optional;
	};
	
	## This function can be called at any time to determine if the cluster
	## framework is being enabled for this run.
	global is_enabled: function(): bool;
	
	## This function can be called at any time to determine what type of
	## cluster node the current Bro instance is going to be acting as.
	## If :bro:id:`Cluster::is_enabled` returns false, then
	## :bro:enum:`Cluster::NONE` is returned.
	global local_node_type: function(): NodeType;
	
	## This gives the value for the number of workers currently connected to,
	## and it's maintained internally by the cluster framework.  It's 
	## primarily intended for use by managers to find out how many workers 
	## should be responding to requests.
	global worker_count: count = 0;
	
	## The cluster layout definition.  This should be placed into a filter
	## named cluster-layout.bro somewhere in the BROPATH.  It will be 
	## automatically loaded if the CLUSTER_NODE environment variable is set.
	const nodes: table[string] of Node = {} &redef;
	
	## This is usually supplied on the command line for each instance
	## of the cluster that is started up.
	const node = getenv("CLUSTER_NODE") &redef;
}

function is_enabled(): bool
	{
	return (node != "");
	}

function local_node_type(): NodeType
	{
	return is_enabled() ? nodes[node]$node_type : NONE;
	}
	

event remote_connection_handshake_done(p: event_peer)
	{
	if ( nodes[p$descr]$node_type == WORKER )
		++worker_count;
	}
event remote_connection_closed(p: event_peer)
	{
	if ( nodes[p$descr]$node_type == WORKER )
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
	
	Log::create_stream(CLUSTER, [$columns=Info]);
	}
