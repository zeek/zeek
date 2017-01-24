##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load base/frameworks/broker/communication
@load base/frameworks/cluster

@if ( Cluster::node in Cluster::nodes )

module Cluster;

function update_node(cname: string, name: string, connect: bool, retry: interval)
	{
	if ( name in Broker::nodes )
		{
		# Check if old retry time is smaller than new one and keep the smaller one
		local o_retry = Broker::nodes[name]$retry;
		if ( o_retry < retry )
			retry = o_retry;

		# update connect field
		Broker::nodes[cname]$connect = Broker::nodes[name]$connect || connect;
		# update retry field
		Broker::nodes[cname]$retry = retry;
		}
	else
		{
		Broker::nodes[cname] = [$ip=nodes[name]$ip, $p=nodes[name]$p,
		                        $connect=connect, $retry=retry];
		}
	}

function process_node(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	# Connections from the control node for runtime control
	# Every node in a cluster is eligible for control from this host.
	if ( CONTROL in n$node_roles )
		Broker::nodes["control"] = [$ip=n$ip, $connect=F];

	for ( role in me$node_roles )
		{
		if ( role == MANAGER )
			process_node_manager(name);
		else if ( role == LOGGER )
			process_node_logger(name);
		else if ( role == DATANODE )
			process_node_datanode(name);
		else if ( role == WORKER )
			process_node_worker(name);
		}
	}

function process_node_manager(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	if ( LOGGER in n$node_roles && me?$logger && me$logger == name )
		update_node(name, name, T, 1min);

	if ( WORKER in n$node_roles && n?$manager && n$manager == node )
		update_node(name, name, F, 1sec);

	if ( DATANODE in n$node_roles && n?$manager && n$manager == node )
		update_node(name, name, F, 1sec);

	if ( TIME_MACHINE in n$node_roles && me?$time_machine && me$time_machine == name )
		update_node("time-machine", name, T, 1min);
	}

function process_node_datanode(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	if ( LOGGER in n$node_roles && me?$logger && me$logger == name )
		update_node(name, name, T, 1min);

	if ( WORKER in n$node_roles && n?$datanodes && node in n$datanodes )
		update_node(name, name, F, 1sec);

	# accepts connections from the previous one.
	if ( DATANODE in n$node_roles )
		{
		if ( n?$datanodes )
			update_node(name, name, T, 1min);

		else if ( me?$datanodes && name in me$datanodes )
			{
			print "update node ", name, ", ", name;
			update_node(name, name, F, 1sec);
			}
		}

	# Finally the manager, to send status updates to.
	if ( MANAGER in n$node_roles )
		{
		if ( me?$manager && me$manager == name ) # name = manager
			update_node(name, name, T, 1mins);
		}
	}

function process_node_logger(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	if ( MANAGER in n$node_roles && n?$logger && n$logger == node )
		update_node(name, name, F, 0sec);

	if ( DATANODE in n$node_roles && n?$logger && n$logger == node )
		update_node(name, name, F, 0sec);

	if ( WORKER in n$node_roles && n?$logger && n$logger == node )
		update_node(name, name, F, 0sec);
	}

function process_node_worker(name: string)
	{
	local n = nodes[name]; # the remote node
	local me = nodes[node]; # the local node

	if ( MANAGER in n$node_roles )
		{
		if ( me?$manager && me$manager == name ) # name = manager
			update_node(name, name, T, 1mins);
		}

	if ( LOGGER in n$node_roles )
		{
		if ( me?$logger && me$logger == name ) # name = logger
			update_node(name, name, T, 1mins);
		}

	if ( DATANODE in n$node_roles )
		{
		if ( me?$datanodes && name in me$datanodes ) # name = datanode
			update_node(name, name, T, 1mins);
		}

	if ( TIME_MACHINE in n$node_roles )
		{
		if ( me?$time_machine && me$time_machine == name )
			update_node("time-machine", name, T, 1mins);
		}
	}

# Event to add a new node or to update an existing node
event Cluster::update_cluster_node(name: string, roles: set[string], ip: string, p: string, interface: string, manager: string, workers: set[string], datanodes: set[string])
	{
	# Build the Node entry for the new/updated node
	local new_node = Node($node_roles=get_roles_enum(roles),
							$ip = to_addr(ip),
							$interface = interface,
							$p = to_port(p),
							$manager = manager,
							$workers = workers,
							$datanodes = datanodes);

	local lnode = nodes[node];
	local set_roles = F;
	local update_connections = F;
	if ( name == node ) # This is an update for us
		{
		print " * Local node received an update from control";
		if ( enum_set_eq(new_node$node_roles, lnode$node_roles) )
			set_roles = T;

		if ( new_node?$datanodes != lnode?$datanodes
				|| !string_set_eq(new_node$datanodes, lnode$datanodes) )
			update_connections = T;

		if ( new_node?$workers != lnode?$workers
				|| !string_set_eq(new_node$workers, lnode$workers) )
			update_connections = T;

		if ( new_node?$manager != lnode?$manager
				|| new_node$manager != lnode$manager )
			update_connections = T;

		# we have to rethink our relationship to all other nodes
		for ( n in Broker::nodes )
			delete Broker::nodes[n];

		}
	else if ( name in nodes ) # This is an update for another node
		{
		#print " * We received an update for node ", name;
		update_connections = T;

		# we have to rethink our relationship just to this node
		if ( name in Broker::nodes )
			delete Broker::nodes[name];
		}
	else # New node
		{
		#print " * Node ", name, " joined the cluster";
		update_connections = T;
		}

	# ... and store the entry in the node list
	Cluster::nodes[name] = new_node;
	#print "new_node data? ", new_node$datanodes;

	for ( name in nodes )
		process_node(name);

	if ( set_roles )
		Cluster::set_local_roles();
	if ( update_connections )
		event Cluster::node_updated(name);
}

#TODO remove node from cluster
# - remove it from nodes datastructure
event Cluster::remove_cluster_node(name: string)
	{
	print "remove node ", name;
	}

event bro_init() &priority=9
	{
	for ( name in nodes )
		process_node(name);
	}

@endif
