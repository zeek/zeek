# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/notice.log

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef enum Notice::Type += {
	Test_Notice,
};

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}

event delayed_notice()
	{
	if ( Cluster::node == "worker-1" )
		NOTICE([$note=Test_Notice, $msg="test notice!"]);
	}

event ready()
	{
	schedule 1secs { delayed_notice() };
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;

event Cluster::node_up(name: string, id: string)
	{
	peer_count = peer_count + 1;

	if ( peer_count == 2 )
		Broker::publish(Cluster::worker_topic, ready);
	}

event Notice::log_notice(rec: Notice::Info)
	{
	terminate();
	}

@endif
