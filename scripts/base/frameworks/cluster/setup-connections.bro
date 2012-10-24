##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load base/frameworks/communication

@if ( Cluster::node in Cluster::nodes )

module Cluster;

event bro_init() &priority=9
	{
	local me = nodes[node];
	
	for ( i in Cluster::nodes )
		{
		local n = nodes[i];

		# Connections from the control node for runtime control and update events.
		# Every node in a cluster is eligible for control from this host.
		if ( n$node_type == CONTROL )
			Communication::nodes["control"] = [$host=n$ip, $zone_id=n$zone_id,
			                                   $connect=F, $class="control",
			                                   $events=control_events];
		
		if ( me$node_type == MANAGER )
			{
			if ( n$node_type == WORKER && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=worker2manager_events, $request_logs=T];
			
			if ( n$node_type == PROXY && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=proxy2manager_events, $request_logs=T];
				
			if ( n$node_type == TIME_MACHINE && me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip,
				                                        $zone_id=nodes[i]$zone_id,
				                                        $p=nodes[i]$p,
				                                        $connect=T, $retry=1min,
				                                        $events=tm2manager_events];
			}
		
		else if ( me$node_type == PROXY )
			{
			if ( n$node_type == WORKER && n$proxy == node )
				Communication::nodes[i] =
					[$host=n$ip, $zone_id=n$zone_id, $connect=F, $class=i,
					 $sync=T, $auth=T, $events=worker2proxy_events];
			
			# accepts connections from the previous one. 
			# (This is not ideal for setups with many proxies)
			# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
			if ( n$node_type == PROXY )
				{
				if ( n?$proxy )
					Communication::nodes[i]
					     = [$host=n$ip, $zone_id=n$zone_id, $p=n$p,
					        $connect=T, $auth=F, $sync=T, $retry=1mins];
				else if ( me?$proxy && me$proxy == i )
					Communication::nodes[me$proxy]
					     = [$host=nodes[i]$ip, $zone_id=nodes[i]$zone_id,
					        $connect=F, $auth=T, $sync=T];
				}
			
			# Finally the manager, to send it status updates.
			if ( n$node_type == MANAGER && me$manager == i )
				Communication::nodes["manager"] = [$host=nodes[i]$ip, 
				                                   $zone_id=nodes[i]$zone_id, 
				                                   $p=nodes[i]$p, 
				                                   $connect=T, $retry=1mins, 
				                                   $class=node,
				                                   $events=manager2proxy_events];
			}
		else if ( me$node_type == WORKER )
			{
			if ( n$node_type == MANAGER && me$manager == i )
				Communication::nodes["manager"] = [$host=nodes[i]$ip, 
				                                   $zone_id=nodes[i]$zone_id,
				                                   $p=nodes[i]$p,
				                                   $connect=T, $retry=1mins, 
				                                   $class=node, 
				                                   $events=manager2worker_events];
			
			if ( n$node_type == PROXY && me$proxy == i )
				Communication::nodes["proxy"] = [$host=nodes[i]$ip, 
				                                 $zone_id=nodes[i]$zone_id,
				                                 $p=nodes[i]$p,
				                                 $connect=T, $retry=1mins, 
				                                 $sync=T, $class=node, 
				                                 $events=proxy2worker_events];
			
			if ( n$node_type == TIME_MACHINE && 
			     me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip, 
				                                        $zone_id=nodes[i]$zone_id,
				                                        $p=nodes[i]$p,
				                                        $connect=T, 
				                                        $retry=1min,
				                                        $events=tm2worker_events];
			
			}
		}
	}

@endif
