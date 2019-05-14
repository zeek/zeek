# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 15

# @TEST-EXEC: btest-diff manager-1/.stdout
#
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
	local r1: SumStats::Reducer = [$stream="test.metric", 
	                               $apply=set(SumStats::TOPK)];
	SumStats::create([$name="topk-test", 
	                  $epoch=5secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["test.metric"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, 5);
	                  	print fmt("Top entries for key %s", key$str);
	                  	for ( element in s ) 
	                  		{
	                  		print fmt("Num: %d, count: %d, epsilon: %d", s[element]$num, topk_count(r$topk, s[element]), topk_epsilon(r$topk, s[element]));
	                  		}
	                  	},
	                  $epoch_finished(ts: time) = 
	                  	{
	                  	terminate();
	                  	}]);


	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

global ready_for_data: event();

event zeek_init()
	{
	Broker::auto_publish(Cluster::worker_topic, ready_for_data);
	}

event ready_for_data()
	{
	const loop_v: vector of count = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100};


	if ( Cluster::node == "worker-1" )
		{

		local a: count;
		a = 0;

		for ( i in loop_v ) 
			{
			a = a + 1;
			for ( j in loop_v )
				{
				if ( i < j ) 
					SumStats::observe("test.metric", [$str="counter"], [$num=a]);
				}
			}
		

		SumStats::observe("test.metric", [$str="two"], [$num=1]);
		SumStats::observe("test.metric", [$str="two"], [$num=1]);
		}
	if ( Cluster::node == "worker-2" )
		{
		SumStats::observe("test.metric", [$str="two"], [$num=2]);
		SumStats::observe("test.metric", [$str="two"], [$num=2]);
		SumStats::observe("test.metric", [$str="two"], [$num=2]);
		SumStats::observe("test.metric", [$str="two"], [$num=2]);
		SumStats::observe("test.metric", [$str="two"], [$num=1]);

		for ( i in loop_v )
			{
			SumStats::observe("test.metric", [$str="counter"], [$num=995]);
			}
		}
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peer_count;
	if ( peer_count == 2 )
		event ready_for_data();
	}

@endif

