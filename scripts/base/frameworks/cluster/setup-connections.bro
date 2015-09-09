##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load base/frameworks/communication

@if ( Cluster::node in Cluster::nodes )

module Cluster;

function process_node_manager(i: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( n$node_type == WORKER && n$manager == node )
		Communication::nodes[i] =
		    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
		     $class=i, $request_logs=T];
			
	if ( n$node_type == DATANODE && n$manager == node )
		Communication::nodes[i] =
		    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
		     $class=i, $request_logs=T];
				
	if ( n$node_type == TIME_MACHINE && me?$time_machine && me$time_machine == i )
		Communication::nodes["time-machine"] = [$host=nodes[i]$ip,
		                                        $zone_id=nodes[i]$zone_id,
		                                        $p=nodes[i]$p,
		                                        $connect=T, $retry=1min];
	}

function process_node_datanode(i: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( n$node_type == WORKER && n$datanode == node )
		Communication::nodes[i] =
			[$host=n$ip, $zone_id=n$zone_id, $connect=F, $class=i];
		
	# accepts connections from the previous one. 
	# (This is not ideal for setups with many proxies)
	# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
	if ( n$node_type == DATANODE )
		{
		if ( n?$datanode )
			Communication::nodes[i]
			     = [$host=n$ip, $zone_id=n$zone_id, $p=n$p, $connect=T, $retry=1mins];
		else if ( me?$datanode && me$datanode == i )
			Communication::nodes[me$datanode]
			     = [$host=nodes[i]$ip, $zone_id=nodes[i]$zone_id, $connect=F];
		}
			
	# Finally the manager, to send status updates to.
	if ( n$node_type == MANAGER && me$manager == i )
		Communication::nodes[i] = [$host=nodes[i]$ip, 
	                               $zone_id=nodes[i]$zone_id, 
	                               $p=nodes[i]$p, 
	                               $connect=T, $retry=1mins, 
	                               $class=node];
	}

function process_node_worker(i: string, n: Cluster::Node, me: Cluster::Node)
	{

	if ( n$node_type == MANAGER && me$manager == i )
		Communication::nodes[i] = [$host=nodes[i]$ip, 
		                           $zone_id=nodes[i]$zone_id,
		                           $p=nodes[i]$p,
		                           $connect=T, $retry=1mins, 
		                           $class=node];
			
	if ( n$node_type == DATANODE && me$datanode == i )
		Communication::nodes[i] = [$host=nodes[i]$ip, 
		                           $zone_id=nodes[i]$zone_id,
		                           $p=nodes[i]$p,
		                           $connect=T, $retry=1mins, 
		                           $class=node];
			
	if ( n$node_type == TIME_MACHINE && 
	     me?$time_machine && me$time_machine == i )
		Communication::nodes["time-machine"] = [$host=nodes[i]$ip, 
		                                        $zone_id=nodes[i]$zone_id,
		                                        $p=nodes[i]$p,
		                                        $connect=T, 
		                                        $retry=1min];
	}

function process_node(i: string, n: Cluster::Node, me: Cluster::Node)
	{
		# Connections from the control node for runtime control
		# Every node in a cluster is eligible for control from this host.
		if ( n$node_type == CONTROL)
			Communication::nodes["control"] = [$host=n$ip, $zone_id=n$zone_id,
			                                   $connect=F, $class="control"];

		if ( me$node_type == MANAGER )
			process_node_manager(i, n, me);
		else if ( me$node_type == DATANODE )
			process_node_datanode(i, n, me);
		else if ( me$node_type == WORKER )
			process_node_worker(i, n, me);
	}

event bro_init() &priority=9
	{
	local me = nodes[node];

	for ( i in Cluster::nodes )
		{
		local n = nodes[i];
		process_node(i, n, me);
		}
	}

@endif
