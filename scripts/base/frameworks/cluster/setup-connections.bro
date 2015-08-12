##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load base/frameworks/communication

@if ( Cluster::node in Cluster::nodes )

module Cluster;

function process_node_manager(name: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( WORKER in n$node_roles && n$manager == node )
		Communication::nodes[name] =
		    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
		     $class=name, $request_logs=T];
			
	if ( DATANODE in n$node_roles && n$manager == node )
		Communication::nodes[name] =
		    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
		     $class=name, $request_logs=T];
				
	if ( TIME_MACHINE in n$node_roles && me?$time_machine && me$time_machine == name )
		Communication::nodes["time-machine"] = [$host=nodes[name]$ip,
		                                        $zone_id=nodes[name]$zone_id,
		                                        $p=nodes[name]$p,
		                                        $connect=T, $retry=1min];
	}

function process_node_datanode(name: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( WORKER in n$node_roles && n$datanode == node )
		Communication::nodes[name] =
			[$host=n$ip, $zone_id=n$zone_id, $connect=F, $class=name];
		
	# accepts connections from the previous one. 
	# (This is not ideal for setups with many proxies)
	# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
	if ( DATANODE in n$node_roles )
		{
		if ( n?$datanode)
			Communication::nodes[name]
			     = [$host=n$ip, $zone_id=n$zone_id, $p=n$p, $connect=T, $retry=1mins];
		else if ( me?$datanode && me$datanode == name )
			Communication::nodes[me$datanode]
			     = [$host=nodes[name]$ip, $zone_id=nodes[name]$zone_id, $connect=F];
		}
			
	# Finally the manager, to send status updates to.
	if ( MANAGER in n$node_roles && me$manager == name )
		## name = manager 
		Communication::nodes[name] = [$host=nodes[name]$ip, 
	                               $zone_id=nodes[name]$zone_id, 
	                               $p=nodes[name]$p, 
	                               $connect=T, $retry=1mins, 
	                               $class=node];
	}

function process_node_worker(name: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( MANAGER in n$node_roles && me$manager == name )
		## name = manager 
		Communication::nodes[name] = [$host=nodes[name]$ip, 
		                           $zone_id=nodes[name]$zone_id,
		                           $p=nodes[name]$p,
		                           $connect=T, $retry=1mins, 
		                           $class=node];
			
	if ( DATANODE in n$node_roles && me$datanode == name )
		## name = datanode 
		Communication::nodes[name] = [$host=nodes[name]$ip, 
		                           $zone_id=nodes[name]$zone_id,
		                           $p=nodes[name]$p,
		                           $connect=T, $retry=1mins, 
		                           $class=node];
			
	if ( TIME_MACHINE in n$node_roles && 
	     me?$time_machine && me$time_machine == name )
		Communication::nodes["time-machine"] = [$host=nodes[name]$ip, 
		                                        $zone_id=nodes[name]$zone_id,
		                                        $p=nodes[name]$p,
		                                        $connect=T, 
		                                        $retry=1min];
	}

function process_node(name: string, n: Cluster::Node, me: Cluster::Node)
	{
		# Connections from the control node for runtime control
		# Every node in a cluster is eligible for control from this host.
		if ( CONTROL in n$node_roles )
			Communication::nodes["control"] = [$host=n$ip, $zone_id=n$zone_id,
			                                   $connect=F, $class="control"];

		if ( MANAGER in me$node_roles )
			process_node_manager(name, n, me);
		else if ( DATANODE in me$node_roles )
			process_node_datanode(name, n, me);
		else if ( WORKER in me$node_roles )
			process_node_worker(name, n, me);
	}

event bro_init() &priority=9
	{
	local me = nodes[node];
	
	for ( name in Cluster::nodes )
		{
		local n = nodes[name];
		process_node(name, n, me);
		}
	}

@endif
