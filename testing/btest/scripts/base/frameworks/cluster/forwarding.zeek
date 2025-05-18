# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@load policy/frameworks/cluster/experimental

redef Broker::forward_messages = T;

event forwarded_event()
	{
	print "got forwarded event";

	if ( Cluster::node == "manager" )
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
	if ( Cluster::node == "manager" )
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
