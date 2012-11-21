# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT 
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/notice.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef enum Notice::Type += {
	Test_Notice,
};

redef enum Metrics::ID += {
	TEST_METRIC,
};

event bro_init() &priority=5
	{
	Metrics::add_filter(TEST_METRIC,
		[$name="foo-bar",
		 $break_interval=1hr,
		 $note=Test_Notice,
		 $notice_threshold=100,
		 $log=T]);
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

event Notice::log_notice(rec: Notice::Info)
	{
	terminate_communication();
	terminate();
	}

@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )

event do_metrics(i: count)
	{
	# Worker-1 will trigger an intermediate update and then if everything
	# works correctly, the data from worker-2 will hit the threshold and
	# should trigger the notice.
	Metrics::add_data(TEST_METRIC, [$host=1.2.3.4], i);
	}

event bro_init()
	{
	if ( Cluster::node == "worker-1" )
		schedule 2sec { do_metrics(99) };
	if ( Cluster::node == "worker-2" )
		event do_metrics(1);
	}

@endif
