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
		PROXY,
		## The node type doing all the actual traffic analysis.
		WORKER,
		## A node acting as a traffic recorder using the
		## `Time Machine <http://bro.org/community/time-machine.html>`_
		## software.
		TIME_MACHINE,
	};
	
	## Events raised by a manager and handled by the workers.
	const manager2worker_events = /Drop::.*/ &redef;
	
	## Events raised by a manager and handled by proxies.
	const manager2proxy_events = /EMPTY/ &redef;
	
	## Events raised by proxies and handled by a manager.
	const proxy2manager_events = /EMPTY/ &redef;
	
	## Events raised by proxies and handled by workers.
	const proxy2worker_events = /EMPTY/ &redef;
	
	## Events raised by workers and handled by a manager.
	const worker2manager_events = /(TimeMachine::command|Drop::.*)/ &redef;
	
	## Events raised by workers and handled by proxies.
	const worker2proxy_events = /EMPTY/ &redef;
	
	## Events raised by TimeMachine instances and handled by a manager.
	const tm2manager_events = /EMPTY/ &redef;
	
	## Events raised by TimeMachine instances and handled by workers.
	const tm2worker_events = /EMPTY/ &redef;
	
	## Events sent by the control host (i.e. BroControl) when dynamically 
	## connecting to a running instance to update settings or request data.
	const control_events = Control::controller_events &redef;
	
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
		## Name of the proxy node this node uses.  For workers and managers.
		proxy:        string      &optional;
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
}

function is_enabled(): bool
	{
	return (node != "");
	}

function local_node_type(): NodeType
	{
	return is_enabled() ? nodes[node]$node_type : NONE;
	}

event remote_connection_handshake_done(p: event_peer) &priority=5
	{
	if ( p$descr in nodes && nodes[p$descr]$node_type == WORKER )
		++worker_count;
	}

event remote_connection_closed(p: event_peer) &priority=5
	{
	if ( p$descr in nodes && nodes[p$descr]$node_type == WORKER )
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
	
	Log::create_stream(Cluster::LOG, [$columns=Info]);
	}
