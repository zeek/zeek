
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
			Communication::nodes["control"] = [$host=n$ip, $connect=F,
			                                   $class="control", $events=control_events];
		
		# The node being started up is this node so we create a dummy 
		# communication entry to point at this host for control.
		if ( i == node )
			Communication::nodes[i] = [$host=n$ip, $p=n$p, $connect=F, $class="control", $sync=F];
		
		if ( me$node_type == MANAGER )
			{
			if ( n$node_type == WORKER && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $connect=F,
				     $class=i, $events=worker_events, $request_logs=T];
			
			if ( n$node_type == PROXY && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $connect=F,
				     $class=i, $events=proxy_events, $request_logs=T];
				
			if ( n$node_type == TIME_MACHINE && me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip, $p=nodes[i]$p,
				                                        $connect=T, $retry=1min];
			}
		
		else if ( me$node_type == PROXY )
			{
			if ( n$node_type == WORKER && n$proxy == node )
				Communication::nodes[i] =
				    [$host=n$ip, $connect=F, $class=i, $events=worker_events];
			
			# accepts connections from the previous one. 
			# (This is not ideal for setups with many proxies)
			# FIXME: Once we're using multiple proxies, we should also figure out some $class scheme ...
			if ( n$node_type == PROXY )
				{
				if ( n?$proxy )
					Communication::nodes[i]
					     = [$host=n$ip, $p=n$p,
					        $connect=T, $auth=F, $sync=T, $retry=1mins];
				else if ( me?$proxy && me$proxy == i )
					Communication::nodes[me$proxy]
					     = [$host=nodes[i]$ip, $connect=F, $auth=T, $sync=T];
				}
			
			# Finally the manager, to send it status updates.
			if ( n$node_type == MANAGER && me$manager == i )
				Communication::nodes["manager"] = [$host=nodes[i]$ip, $p=nodes[i]$p, 
				                                   $connect=T, $retry=1mins, 
				                                   $class=node];
			}
		
		else if ( me$node_type == WORKER )
			{
			if ( n$node_type == MANAGER && me$manager == i )
				Communication::nodes["manager"] = [$host=nodes[i]$ip, $p=nodes[i]$p,
				                                   $connect=T, $retry=1mins, 
				                                   $class=node];
			
			if ( n$node_type == PROXY && me$proxy == i )
				Communication::nodes["proxy"] = [$host=nodes[i]$ip, $p=nodes[i]$p,
				                                 $connect=T, $retry=1mins, 
				                                 $class=node];
			
			if ( n$node_type == TIME_MACHINE && me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip, $p=nodes[i]$p,
				                                        $connect=T, $retry=1min];
			
			}
		}
	}