# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff manager-1/metrics.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["proxy-1"]   = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=37758/tcp, $manager="manager-1", $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

event bro_init() &priority=5
	{
	Metrics::add_filter("test.metric", 
	                    [$every=3secs,
	                     $measure=set(Metrics::SUM, Metrics::MIN, Metrics::MAX, Metrics::AVG, Metrics::STD_DEV, Metrics::VARIANCE)]);
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
	if ( Cluster::node == "worker-1" )
		{
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=34]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=30]);
		Metrics::add_data("test.metric", [$host=6.5.4.3], [$num=1]);
		Metrics::add_data("test.metric", [$host=7.2.1.5], [$num=54]);
		}
	if ( Cluster::node == "worker-2" )
		{
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=75]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=30]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=3]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=57]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=52]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=61]);
		Metrics::add_data("test.metric", [$host=1.2.3.4], [$num=95]);
		Metrics::add_data("test.metric", [$host=6.5.4.3], [$num=5]);
		Metrics::add_data("test.metric", [$host=7.2.1.5], [$num=91]);
		}
	}

@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global n = 0;
global peer_count = 0;

event Metrics::log_metrics(rec: Metrics::Info)
	{
	++n;
	if ( n == 3 )
		{
		terminate_communication();
		terminate();
		}
	}

event remote_connection_handshake_done(p: event_peer)
	{
	print p;
	++peer_count;
	if ( peer_count == 3 )
		event ready_for_data();
	}

@endif
