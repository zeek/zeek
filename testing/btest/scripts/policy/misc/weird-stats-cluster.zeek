# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: btest-diff manager/weird_stats.log

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
	if ( Cluster::node == "manager" )
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
