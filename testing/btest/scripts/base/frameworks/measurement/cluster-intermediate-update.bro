# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 3
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT 
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff manager-1/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

event bro_init() &priority=5
	{
	local r1: Measurement::Reducer = [$stream="test.metric", $apply=set(Measurement::SUM)];
	Measurement::create([$epoch=1hr,
	                     $reducers=set(r1),
	                     $threshold_val(key: Measurement::Key, result: Measurement::Result) =
	                     	{
	                     	return double_to_count(result["test.metric"]$sum);
	                     	},
	                     $threshold=100,
	                     $threshold_crossed(key: Measurement::Key, result: Measurement::Result) =
	                     	{
	                     	print fmt("A test metric threshold was crossed with a value of: %.1f", result["test.metric"]$sum);
	                     	terminate();
	                     	}
	                    ]);
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

event do_metrics(i: count)
	{
	# Worker-1 will trigger an intermediate update and then if everything
	# works correctly, the data from worker-2 will hit the threshold and
	# should trigger the notice.
	Measurement::add_data("test.metric", [$host=1.2.3.4], [$num=i]);
	}

event remote_connection_handshake_done(p: event_peer)
	{
	if ( p$descr == "manager-1" )
		{
		if ( Cluster::node == "worker-1" )
			schedule 0.1sec { do_metrics(1) };
		if ( Cluster::node == "worker-2" )
			schedule 0.5sec { do_metrics(99) };
		}
	}
