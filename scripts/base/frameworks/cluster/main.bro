##! A framework for establishing and controlling a cluster of Bro instances.
##! In order to use the cluster framework, a script named
##! ``cluster-layout.bro`` must exist somewhere in Bro's script search path
##! which has a cluster definition of the :bro:id:`Cluster::nodes` variable.
##! The ``CLUSTER_NODE`` environment variable or :bro:id:`Cluster::node`
##! must also be set and the cluster framework loaded as a package like
##! ``@load base/frameworks/cluster``.

@load base/frameworks/control
@load base/frameworks/logging
@load misc/trim-trace-file

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

	## Roles of nodes that are allowed to participate in the cluster
	## configuration.
	type NodeRole: enum {
		## A dummy node role indicating the local node is not operating
		## within a cluster.
		NONE,
		## A node role which is allowed to view/manipulate the configuration
		## of other nodes in the cluster.
		CONTROL,
		## A node role responsible for log and policy management.
		MANAGER,
		## A node role for relaying worker node communication and synchronizing
		## worker node state.
		DATANODE,
		## A node role for storing logs
		LOGNODE,
		## The node role doing all the actual traffic analysis.
		WORKER,
		## A node role that is part of a deep cluster configuration
		PEER,
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
	
	## Add events for adding new nodes and removing old nodes
	redef Control::controllee_events: set[string] += {"Cluster::update_cluster_node", "Cluster::remove_cluster_node"};

	## The prefix used for subscribing and publishing events
	const pub_sub_prefix : string = "bro/event/cluster/" &redef;

	# The Cluster-IDs of the particular cluster this node is part of 
	const cluster_id : string = "" &redef;

	## Record type to indicate a node in a cluster.
	type Node: record {
		## Identifies the type of cluster node in this node's configuration.
		## Roles of a node
		node_roles: 	set[NodeRole];
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
	
	## Process the cluster-layout entry and add entries to Communication::nodes
	##
	## name: the name of the node
	global process_node: function(name: string);
	global process_node_manager: function(name: string);
	global process_node_datanode: function(name: string);
	global process_node_lognode: function(name: string);
	global process_node_worker: function(name: string);

	## This function can be called at any time to determine if the cluster
	## framework is being enabled for this run.
	##
	## Returns: True if :bro:id:`Cluster::node` has been set.
	global is_enabled: function(): bool;

	## Register events with broker that the local node will publish.
	##
	## prefix: the broker pub-sub prefix
	## event_list: a list of events to be published via this prefix
	global register_broker_events: function(prefix: string, event_list: set[string]);

	## Unregister events with broker that the local node will publish.
	##
	## prefix: the broker pub-sub prefix
	## event_list: a list of events to be published via this prefix
	global unregister_broker_events: function(prefix: string, event_list: set[string]);

	## This function can be called at any time to determine the types of
	## cluster roles the current Bro instance has.
	##
	## Returns: true if local node has that role, false otherwise
	global has_local_role: function(role: NodeRole): bool;

	## Assign the local node all of its assigned roles.
	##
	## reset: bool that determines if roles are assigned on the existing state
	##        or if roles are assigned to a fresh initial state
	global set_local_roles:function(reset: bool);

	## Functions to set the node role dynamically.
	global set_role_manager:function(reset: bool);
	global set_role_datanode:function(reset: bool);
	global set_role_lognode:function(reset: bool);
	global set_role_worker:function(reset: bool);

	## Helper function
	##
	## string of NodeRoles as input, 
	## returns the node roles as a set of enums
	global get_roles_enum: function(roles: set[string]): set[NodeRole];

	## Helper function
	##
	## String as input that is separated by commas
	## Returns a set of strings
	global get_set: function(st: string): set[string];

	## Compares two NodeRole sets with each other.
	##
	## set1: set of NodeRole
	## set2: set of NodeRole
	## return bool
	global enum_set_eq: function(set1: set[NodeRole], set2: set[NodeRole]): bool;

	## Compares two sets of strings with each other.
	##
	## set1: set of string
	## set2: set of string
	## return bool
	global string_set_eq: function(set1: set[string], set2: set[string]): bool;

	global update_node: function(cname: string, name: string, connect: bool, retry: interval);

	## Add an additional node dynamically to a cluster.
	## 
	## name: name of the node
	## roles: supported roles by the node
	## ip: ip of the node
	## zone_id: zone_id of the node
	## p: port this node listens on
	## interface: interface this node monitors
	## manager: responsible manager node
	## datanode: responsible datanode
	global update_cluster_node: event(name: string, roles: set[string], ip: string, p: string, interface: string, manager: string, workers: set[string], datanode: string);

	## Remove a node dynamically from a cluster.
	##
	## name: the name of the node
	global remove_cluster_node: event(name: string);

	## Event that node information has been updated
	##
	## node_name: the name of the updated node
	global node_updated: event(node_name: string);

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

	## The local datastore that can be either master or clone.
	global cluster_store: opaque of Broker::Handle;

	# Set the correct name of this endpoint according to cluster-layout.
	redef Broker::endpoint_name = node;

	## Interval for retrying failed connections between cluster nodes.
	const retry_interval = 1min &redef;
}

function get_set(st: string): set[string]
	{
	local node_set: set[string];
	local node_vec = split_string(st, /(, )/);
	for ( s in node_vec )
		{
		local s2 = strip(node_vec[s]);
		add node_set[s2];
		}
	return node_set;
	}

function get_roles_enum(roles: set[string]): set[NodeRole]
	{
	# Get roles of this node as enums.
	local node_r: set[NodeRole];
	for ( r in roles )
		{
		if ( r == "Cluster::MANAGER" )
			add node_r[Cluster::MANAGER];
		else if ( r == "Cluster::DATANODE" )
			add node_r[Cluster::DATANODE];
		else if ( r == "Cluster::LOGNODE" )
			add node_r[Cluster::LOGNODE];
		else if ( r == "Cluster::WORKER" )
			add node_r[Cluster::WORKER];
		}

	return node_r;
	}

function enum_set_eq(set1: set[NodeRole], set2: set[NodeRole]): bool
	{
	if ( |set1| != |set2| )
		return F;
	else
		{
		for ( e in set1 )
			if ( e !in set2 )
				return F;
		}
	return T;
	}

function string_set_eq(set1: set[string], set2: set[string]): bool
	{
	if ( |set1| != |set2| )
		return F;
	else
		{
		for ( e in set1 )
			if ( e !in set2 )
				return F;
		}
	return T;
	}

function is_enabled(): bool
	{
	return (node != "");
	}


function register_broker_events(prefix: string, event_list: set[string])
	{
	Broker::publish_topic(prefix);
	for ( e in event_list )
		{
		Broker::auto_event(prefix, lookup_ID(e));
		}
	}

function unregister_broker_events(prefix: string, event_list: set[string])
	{
	for ( e in event_list )
		Broker::auto_event_stop(prefix, lookup_ID(e));
	}

function has_local_role(role: NodeRole): bool
	{
	if ( !is_enabled() )
		return F;

	if ( node in nodes && nodes[node]?$node_roles && role in nodes[node]$node_roles )
		return T;
		
	return F;
	}

function set_local_roles(reset: bool)
	{
	print " node is ", node;
	# If reset is required, reset the node with the first call to a set_role_*
	# function.
	local reset_node = reset;
	for ( r in nodes[node]$node_roles )
		{
		if ( r == Cluster::MANAGER )
			set_role_manager(reset_node);
		else if ( r == Cluster::DATANODE )
			set_role_datanode(reset_node);
		else if ( r == Cluster::LOGNODE )
			set_role_lognode(reset_node);
		else if ( r == Cluster::WORKER )
			set_role_worker(reset_node);
		else
			next;

		reset_node = F;
		}
	}

function set_role_manager(reset: bool)
	{
	# 1. Don't do any local logging 
	# 2. Turn on remote logging
	# 3. Log rotation interval.
	# 4. Alarm summary mail interval.
	# 5. Rotation postprocessor: use the cluster's delete-log script.
	Log::update_logging(reset, F, T, 24hrs, 24hrs, "delete-log");

	# Subscribe to events and register events with broker for publication by local node
	# Subsribe to prefix
	local prefix = fmt("%s%s/manager/response/", pub_sub_prefix, cluster_id);
	Broker::subscribe_to_events(prefix);

	# Publish: manager2worker_events, manager2datanode_events
	register_broker_events(fmt("%s%s/worker/request/", pub_sub_prefix, cluster_id), manager2worker_events);
	register_broker_events(fmt("%s%s/data/request/", pub_sub_prefix, cluster_id), manager2datanode_events);

	if ( DATANODE !in nodes[node]$node_roles )
		{
		# Create a clone of the master store
		Cluster::cluster_store = Broker::create_clone("cluster-store");
		}
	}

function set_role_datanode(reset: bool)
	{
	# 1. We are the datanode, so do local logging!
	# 2. Make sure that remote logging is disabled.
	# 3. Log rotation interval.
	# 4. Alarm summary mail interval.
	# 5. rotation postprocessor: use the cluster's delete-log script.
	Log::update_logging(reset, F, F, 1hrs, 24hrs, "archive-log");

	# We're processing essentially *only* remote events.
	max_remote_events_processed = 10000;

	# Subscribe to events and register events with broker for publication by local node
	# Subsribe to prefix
	local prefix = fmt("%s%s/data/request/", pub_sub_prefix, cluster_id);
	Broker::subscribe_to_events(prefix);

	# Publish: datanode2manager_events, datanode2worker_events
	prefix = fmt("%s%s/manager/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, datanode2manager_events);
	prefix = fmt("%s%s/worker/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, datanode2worker_events);

	# Create the master store
	Cluster::cluster_store = Broker::create_master("cluster-store");
	}

function set_role_lognode(reset: bool)
	{
	# 1. We are the datanode, so do local logging!
	# 2. Make sure that remote logging is disabled.
	# 3. Log rotation interval.
	# 4. Alarm summary mail interval.
	# 5. rotation postprocessor: use the cluster's delete-log script.
	Log::update_logging(reset, T, F, 1hrs, 24hrs, "archive-log");

	# Susbscribe to logs
	Broker::subscribe_to_logs("bro/log/");

	# We're processing essentially *only* remote events.
	max_remote_events_processed = 10000;

	# Subscribe to events and register events with broker for publication by local node
	# Subsribe to prefix
	local prefix = fmt("%s%s/data/request/", pub_sub_prefix, cluster_id);
	Broker::subscribe_to_events(prefix);

	# Publish: datanode2manager_events, datanode2worker_events
	prefix = fmt("%s%s/manager/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, datanode2manager_events);
	prefix = fmt("%s%s/worker/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, datanode2worker_events);
		
	if ( DATANODE !in nodes[node]$node_roles )
		{
		# Create a clone of the master store
		Cluster::cluster_store = Broker::create_clone("cluster-store");
		}
	}

function set_role_worker(reset: bool)
	{
	# 1. Don't do any local logging.
	# 2. Make sure that remote logging is enabled.
	# 3. Log rotation interval
	# 4. Alarm summary mail interval.
	# 5. rotation postprocessor: use the cluster's delete-log script.
	Log::update_logging(reset, F, T, 24hrs, 24hrs, "delete-log");

	# Subscribe to events and register events with broker for publication by local node
	# Subsribe to prefix
	local prefix = fmt("%s%s/worker/request/", pub_sub_prefix, cluster_id);
	Broker::subscribe_to_events(prefix);

	# Publish: worker2manager_events, worker2datanode_events
	prefix = fmt("%s%s/manager/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, worker2manager_events);
	prefix = fmt("%s%s/data/response/", pub_sub_prefix, cluster_id);
	register_broker_events(prefix, worker2datanode_events);

	# Record all packets into trace file.
	#
	# Note that this only indicates that *if* we are recording packets, we want all
	# of them (rather than just those the core deems sufficiently important).
	# Setting this does not turn recording on. Use '-w <trace>' for that.
	TrimTraceFile::startTrimTraceFile();
	record_all_packets = T;

	if ( DATANODE !in nodes[node]$node_roles )
		{
		# Create a clone of the master store
		Cluster::cluster_store = Broker::create_clone("cluster-store");
		}
	}

event Broker::incoming_connection_established(peer_name: string) &priority=5
	{
	if ( peer_name in nodes && WORKER in nodes[peer_name]$node_roles )
		++worker_count;
	Log::write(Cluster::LOG, [$ts=1, $message="Cluster: incoming connection established"]);
	}

event Broker::incoming_connection_broken(peer_name: string) &priority=5
	{
	if ( peer_name in nodes && WORKER in nodes[peer_name]$node_roles )
		--worker_count;
	Log::write(Cluster::LOG, [$ts=2, $message="Cluster: incoming connection broken"]);
	}

event bro_init() &priority=5
	{
	if ( is_enabled() && node in nodes )
		{
		# set all roles of local node
		set_local_roles(T);
		Log::create_stream(Cluster::LOG, [$columns=Info, $path="cluster"]);
		}
	}
