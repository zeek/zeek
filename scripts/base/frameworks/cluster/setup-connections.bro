##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load base/frameworks/communication
@load base/frameworks/cluster

@if ( Cluster::node in Cluster::nodes )

module Cluster;

function update_node(cname: string, name: string, connect: bool, retry: interval)
	{
	if(name in Communication::nodes )
		{
		# Check if old retry time is smaller than new one and keep the smaller one
		local o_retry = Communication::nodes[name]$retry;
		if(o_retry < retry)
			retry = o_retry;

		# update connect field
		Communication::nodes[cname]$connect = Communication::nodes[name]$connect || connect;
		# update retry field 
		Communication::nodes[cname]$retry= retry;
		}
	else
		{
		Communication::nodes[cname] = [$host=nodes[name]$ip, 
		 	                         		$p=nodes[name]$p,
	 			                       		$connect=connect, 
																	$retry=retry];
		}
	}

function process_node(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	# Connections from the control node for runtime control
	# Every node in a cluster is eligible for control from this host.
	if ( CONTROL in n$node_roles )
		Communication::nodes["control"] = [	$host=n$ip, 
		                                   	$connect=F];

	for ( role in me$node_roles )
		{
		if ( role == MANAGER )
			process_node_manager(name);
		else if ( role == LOGNODE)
			process_node_lognode(name);
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
		
	if ( WORKER in n$node_roles && n$manager == node )
		update_node(name, name, F, 1sec);
			
	if ( DATANODE in n$node_roles && n$manager == node )
		update_node(name, name, F, 1sec);
				
	if ( TIME_MACHINE in n$node_roles && me?$time_machine && me$time_machine == name )
		update_node("time-machine", name, T, 1min);
	}

function process_node_datanode(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	if ( WORKER in n$node_roles && n$datanode == node )
		update_node(name, name, F, 1sec);
		
	# accepts connections from the previous one. 
	# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
	if ( DATANODE in n$node_roles )
		{
		if ( n?$datanode)
			update_node(name, name, T, 1min);

		else if ( me?$datanode && me$datanode == name )
			{
			print "update node ", me$datanode, ", ", name;
			update_node(me$datanode, name, F, 1sec);
			}
		}
			
	# Finally the manager, to send status updates to.
	if ( MANAGER in n$node_roles )
		{
		if ( me$manager == name)# name = manager 
			update_node(name, name, T, 1mins);
		}
	}

function process_node_lognode(name: string)
	{
	local n = nodes[name];
	local me = nodes[node];

	if ( WORKER in n$node_roles && n$datanode == node )
		update_node(name, name, F, 1sec);
		
	# accepts connections from the previous one. 
	# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
	if ( DATANODE in n$node_roles )
		{
		if ( n?$datanode)
			update_node(name, name, T, 1mins);

		else if ( me?$datanode && me$datanode == name )
			update_node(me$datanode, name, F, 1sec);
		}
			
	# Finally the manager, to send status updates to.
	if ( MANAGER in n$node_roles )
		{
		if ( me$manager == name)# name = manager
			update_node(name, name, T, 1mins);
		}
	}

function process_node_worker(name: string)
	{
	local n = nodes[name]; # the remote node
	local me = nodes[node]; # the local node

	if ( MANAGER in n$node_roles )
		{
		if ( me$manager == name ) # name = manager
			update_node(name, name, T, 1mins);
		}

	if ( DATANODE in n$node_roles )
		{
		if ( me$datanode == name ) # name = datanode
			update_node(name, name, T, 1mins);
		}		

	if ( TIME_MACHINE in n$node_roles  )
		{
		if(me?$time_machine && me$time_machine == name)
			update_node("time-machine", name, T, 1mins);
		}
	}

event Cluster::update_cluster_node(name: string, roles: set[string], ip: string, p: string, interface: string, manager: string, workers: set[string], datanode: string)
	{
	# Build the Node entry for the new/updated node
	local new_node = Node($node_roles=get_roles_enum(roles),
												$ip = to_addr(ip),
												$interface = interface,
												$p = to_port(p),
												$manager = manager,
												$workers = workers,
												$datanode = datanode);

	local lnode = nodes[node];
	local set_roles = F;
	local update_connections = F;
	if( name == node ) # This is an update for us
		{
		print " * Local node received an update from control";
		if(enum_set_eq(new_node$node_roles, lnode$node_roles))
			set_roles = T;

		if( new_node?$datanode != lnode?$datanode
				|| new_node$datanode != lnode$datanode )
			update_connections = T;

		if( new_node?$workers != lnode?$workers
				|| !string_set_eq(new_node$workers, lnode$workers) ) 
			update_connections = T;

		if( new_node?$manager != lnode ?$ manager
				|| new_node$manager != lnode$manager )
			update_connections = T;

		# we have to rethink our relationship to all other nodes
		for ( n in Communication::nodes )
			delete Communication::nodes[n];
		
		}
	else if (name in nodes ) # This is an update for another node
		{
		print " * We received an update for node ", name;
		update_connections = T;

		# we have ro rethink our relationship just to this node
		if (name in Communication::nodes)
			delete Communication::nodes[name];
		}
	else # New node
		{
		print " * Node ", name, " joined the cluster";
		update_connections = T;
		}

	# ... and store the entry in the node list
	Cluster::nodes[name] = new_node; 	
	print "new_node data? ", new_node$datanode;

	for (name in nodes)
		process_node(name);

	if(set_roles)
		Cluster::set_local_roles(T);
	if(update_connections)
		event Cluster::node_updated(name);
}

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
