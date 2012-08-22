# Needs perftools support.
#
# @TEST-SERIALIZE: comm
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: btest-bg-run manager-1 HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro -m %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1   bro -m %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1  bro -m -r $TRACES/web.trace --pseudo-realtime %INPUT
# @TEST-EXEC: btest-bg-run worker-2  HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2  bro -m -r $TRACES/web.trace --pseudo-realtime %INPUT
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: btest-diff manager-1/metrics.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1", "worker-2")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef enum Metrics::ID += {
	TEST_METRIC,
};

event bro_init() &priority=5
	{
	Metrics::add_filter(TEST_METRIC, 
		[$name="foo-bar",
		 $break_interval=3secs]);
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

global ready_for_data: event();

redef Cluster::manager2worker_events += /ready_for_data/;

@if ( Cluster::local_node_type() == Cluster::WORKER )

event ready_for_data()
	{
	Metrics::add_data(TEST_METRIC, [$host=1.2.3.4], 3);
	Metrics::add_data(TEST_METRIC, [$host=6.5.4.3], 2);
	Metrics::add_data(TEST_METRIC, [$host=7.2.1.5], 1);
	}

@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global n = 0;
global peer_count = 0;

event Metrics::log_metrics(rec: Metrics::Info)
	{
	n = n + 1;
	if ( n == 3 )
		{
		terminate_communication();
		terminate();
		}
	}

event remote_connection_handshake_done(p: event_peer)
	{
	print p;
	peer_count = peer_count + 1;
	if ( peer_count == 3 )
		{
		event ready_for_data();
		}
	}

@endif
