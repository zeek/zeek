# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: btest-diff manager-1/weird_stats.log

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
};
@TEST-END-FILE

@load misc/weird-stats
@load policy/frameworks/cluster/experimental

redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;
redef WeirdStats::weird_stat_interval = 5secs;

event terminate_me()
	{
	terminate();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event ready_again()
	{
	Reporter::net_weird("weird1");
	schedule 5secs { terminate_me() };
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "manager-1" )
		return;

	local n = 0;

	if ( Cluster::node == "worker-1" )
		{
		while ( n < 1000 )
			{
			Reporter::net_weird("weird1");
			++n;
			}

		Reporter::net_weird("weird3");
		}
	else if ( Cluster::node == "worker-2" )
		{
		while ( n < 1000 )
			{
			Reporter::net_weird("weird1");
			Reporter::net_weird("weird2");
			++n;
			}
		}

	schedule 5secs { ready_again() };
	}
