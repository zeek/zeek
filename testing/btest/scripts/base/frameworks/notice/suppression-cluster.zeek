# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager-1/notice.log

@load base/frameworks/notice
@load policy/frameworks/cluster/experimental

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

global proceed: event();

event do_notice()
	{
	NOTICE([$note=Test_Notice,
	        $msg="test notice!",
	        $identifier="this identifier is static"]);
	Broker::flush_logs();
	Broker::publish(Cluster::node_topic("manager-1"), proceed);
	}

event Notice::suppressed(n: Notice::Info)
	{
	print "suppressed", n$note, n$identifier;

	if ( Cluster::node == "worker-1" )
		terminate();
	}

event Notice::begin_suppression(ts: time, suppress_for: interval, note: Notice::Type,
								identifier: string)
	{
	print "begin suppression", suppress_for, note, identifier;

	if ( Cluster::node == "worker-1" )
		Broker::publish(Cluster::node_topic("manager-1"), proceed);
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

event Cluster::Experimental::cluster_started()
	{
	Broker::publish(Cluster::node_topic("worker-2"), do_notice);
	}

global proceed_count = 0;
event proceed()
	{
	++proceed_count;

	if ( proceed_count == 2 )
		Broker::publish(Cluster::node_topic("worker-1"), do_notice);
	}

@endif
