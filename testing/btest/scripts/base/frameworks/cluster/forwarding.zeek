# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -B broker -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

redef Broker::forward_messages = T;

event forwarded_event()
	{
	print "got forwarded event";

	if ( Cluster::node == "manager-1" )
		print "manager should NOT have raised the forwarded event";

	terminate();
	}

event Cluster::Experimental::cluster_started()
	{
	# note that the publishing node, worker-1, will not receive the forwarded
	# event as Broker's forwarding prevents the message going back to the
	# immediate sender.
	if ( Cluster::node == "worker-1" )
		Broker::publish("test_topic", forwarded_event);
	}

event zeek_init()
	{
	if ( Cluster::node == "manager-1" )
		Broker::forward("test_topic");
	if ( Cluster::node == "worker-1" )
		Broker::subscribe("test_topic");
	if ( Cluster::node == "worker-2" )
		Broker::subscribe("test_topic");
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
