##! This script establishes communication among all nodes in a cluster
##! as defined by :bro:id:`Cluster::nodes`.

@load ./main
@load ./pools
@load base/frameworks/communication
@load base/frameworks/broker

@if ( Cluster::node in Cluster::nodes )

@if ( Cluster::enable_round_robin_logging )
redef Broker::log_topic = Cluster::rr_log_topic;
@endif

module Cluster;

type NamedNode: record {
	name: string;
	node: Node;
};

function nodes_with_type(node_type: NodeType): vector of NamedNode
	{
	local rval: vector of NamedNode = vector();

	for ( name in Cluster::nodes )
		{
		local n = Cluster::nodes[name];

		if ( n$node_type != node_type )
			next;

		rval[|rval|] = NamedNode($name=name, $node=n);
		}

	return rval;
	}

function connect_peer(node_type: NodeType, node_name: string)
	{
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];

		if ( n$name != node_name )
			next;

		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		}
	}

function connect_peers_with_type(node_type: NodeType)
	{
	local rval: vector of NamedNode = vector();
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];
		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		}
	}

event bro_init() &priority=9
	{
	if ( ! use_broker )
		return;

	local self = nodes[node];

	switch ( self$node_type ) {
	case NONE:
		return;
	case CONTROL:
		break;
	case LOGGER:
		Broker::subscribe(Cluster::logger_topic);
		Broker::subscribe(Broker::default_log_topic_prefix);
		break;
	case MANAGER:
		Broker::subscribe(Cluster::manager_topic);

		if ( Cluster::manager_is_logger )
			Broker::subscribe(Broker::default_log_topic_prefix);

		break;
	case PROXY:
		Broker::subscribe(Cluster::proxy_topic);
		break;
	case WORKER:
		Broker::subscribe(Cluster::worker_topic);
		break;
	case TIME_MACHINE:
		Broker::subscribe(Cluster::time_machine_topic);
		break;
	default:
		Reporter::error(fmt("Unhandled cluster node type: %s", self$node_type));
		return;
	}

	Broker::subscribe(Cluster::broadcast_topic);
	Broker::subscribe(node_topic(node));

	Broker::listen(Broker::default_listen_address,
	               self$p,
	               Broker::default_listen_retry);

	Cluster::log(fmt("listening on %s:%s", Broker::default_listen_address, self$p));

	switch ( self$node_type ) {
	case MANAGER:
		connect_peers_with_type(LOGGER);
		connect_peers_with_type(PROXY);

		if ( self?$time_machine )
			connect_peer(TIME_MACHINE, self$time_machine);

		break;
	case PROXY:
		connect_peers_with_type(LOGGER);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		break;
	case WORKER:
		connect_peers_with_type(LOGGER);
		connect_peers_with_type(PROXY);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		if ( self?$time_machine )
			connect_peer(TIME_MACHINE, self$time_machine);

		break;
	}
	}

event bro_init() &priority=-10
	{
	if ( use_broker )
		return;

	local lp = Cluster::nodes[Cluster::node]$p;
	enable_communication();
	listen(Communication::listen_interface,
	       lp,
	       Communication::listen_ssl,
	       Communication::listen_ipv6,
	       Communication::listen_ipv6_zone_id,
	       Communication::listen_retry);
	}

event bro_init() &priority=9
	{
	if ( use_broker )
		return;

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

		if ( me$node_type == LOGGER )
			{
			if ( n$node_type == MANAGER && n$logger == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=manager2logger_events, $request_logs=T];
			if ( n$node_type == PROXY && n$logger == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=proxy2logger_events, $request_logs=T];
			if ( n$node_type == WORKER && n$logger == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=worker2logger_events, $request_logs=T];
			}
		else if ( me$node_type == MANAGER )
			{
			if ( n$node_type == LOGGER && me$logger == i )
				Communication::nodes["logger"] =
				    [$host=n$ip, $zone_id=n$zone_id, $p=n$p,
				     $connect=T, $retry=retry_interval,
				     $class=node];

			if ( n$node_type == WORKER && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=worker2manager_events,
				     $request_logs=Cluster::manager_is_logger];

			if ( n$node_type == PROXY && n$manager == node )
				Communication::nodes[i] =
				    [$host=n$ip, $zone_id=n$zone_id, $connect=F,
				     $class=i, $events=proxy2manager_events,
				     $request_logs=Cluster::manager_is_logger];

			if ( n$node_type == TIME_MACHINE && me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip,
				                                        $zone_id=nodes[i]$zone_id,
				                                        $p=nodes[i]$p,
				                                        $connect=T, $retry=retry_interval,
				                                        $events=tm2manager_events];
			}

		else if ( me$node_type == PROXY )
			{
			if ( n$node_type == LOGGER && me$logger == i )
				Communication::nodes["logger"] =
				    [$host=n$ip, $zone_id=n$zone_id, $p=n$p,
				     $connect=T, $retry=retry_interval,
				     $class=node];

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
					        $connect=T, $auth=F, $sync=T, $retry=retry_interval];
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
				                                   $connect=T, $retry=retry_interval,
				                                   $class=node,
				                                   $events=manager2proxy_events];
			}
		else if ( me$node_type == WORKER )
			{
			if ( n$node_type == LOGGER && me$logger == i )
				Communication::nodes["logger"] =
				    [$host=n$ip, $zone_id=n$zone_id, $p=n$p,
				     $connect=T, $retry=retry_interval,
				     $class=node];

			if ( n$node_type == MANAGER && me$manager == i )
				Communication::nodes["manager"] = [$host=nodes[i]$ip,
				                                   $zone_id=nodes[i]$zone_id,
				                                   $p=nodes[i]$p,
				                                   $connect=T, $retry=retry_interval,
				                                   $class=node,
				                                   $events=manager2worker_events];

			if ( n$node_type == PROXY && me$proxy == i )
				Communication::nodes["proxy"] = [$host=nodes[i]$ip,
				                                 $zone_id=nodes[i]$zone_id,
				                                 $p=nodes[i]$p,
				                                 $connect=T, $retry=retry_interval,
				                                 $sync=T, $class=node,
				                                 $events=proxy2worker_events];

			if ( n$node_type == TIME_MACHINE &&
			     me?$time_machine && me$time_machine == i )
				Communication::nodes["time-machine"] = [$host=nodes[i]$ip,
				                                        $zone_id=nodes[i]$zone_id,
				                                        $p=nodes[i]$p,
				                                        $connect=T,
				                                        $retry=retry_interval,
				                                        $events=tm2worker_events];

			}
		}
	}

@endif
