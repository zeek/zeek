# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT 
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", $apply=set(SumStats::SUM)];
	SumStats::create([$name="test",
	                  $epoch=10secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	print result["test.metric"]$sum;
	                  	},
	                  $epoch_finished(ts: time) = 
	                  	{
	                  	print "End of epoch handler was called";
	                  	terminate();
	                  	},
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["test.metric"]$sum;
	                  	},
	                  $threshold=100.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	print fmt("A test metric threshold was crossed with a value of: %.1f", result["test.metric"]$sum);
	                  	}]);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event do_stats(i: count)
	{
	# Worker-1 will trigger an intermediate update and then if everything
	# works correctly, the data from worker-2 will hit the threshold and
	# should trigger the notice.
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=i]);
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( name == "manager-1" )
		{
		if ( Cluster::node == "worker-1" )
			{
			schedule 0.1sec { do_stats(1) };
			schedule 5secs { do_stats(60) };
			}
		if ( Cluster::node == "worker-2" )
			schedule 0.5sec { do_stats(40) };
		}
	}
