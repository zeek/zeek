# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 6
# @TEST-EXEC: btest-diff manager-1/metrics.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth1"],
};
@TEST-END-FILE

redef enum Metrics::ID += {
	TEST_METRIC,
};

event bro_init() &priority=5
	{
	Metrics::add_filter(TEST_METRIC, 
		[$name="foo-bar",
		 $break_interval=3secs]);
		
	if ( Cluster::local_node_type() == Cluster::WORKER )
		{
		Metrics::add_data(TEST_METRIC, [$host=1.2.3.4], 3);
		Metrics::add_data(TEST_METRIC, [$host=6.5.4.3], 2);
		Metrics::add_data(TEST_METRIC, [$host=7.2.1.5], 1);
		}
	}
