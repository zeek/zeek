# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/notice.log

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1"],
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
	NOTICE([$note=Test_Notice,
	        $msg="test notice!",
	        $identifier="this identifier is static"]);
	}

event ready()
    {
	if ( Cluster::node == "worker-1" )
		schedule 4secs { delayed_notice() };
	if ( Cluster::node == "worker-2" )
		schedule 1secs { delayed_notice() };
    }

event Notice::suppressed(n: Notice::Info)
	{
	if ( Cluster::node == "worker-1" )
		terminate();
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;

event Cluster::node_up(name: string, id: string)
	{
	peer_count = peer_count + 1;

	if ( peer_count == 3 )
		Broker::publish(Cluster::worker_topic, ready);
	}

@endif
