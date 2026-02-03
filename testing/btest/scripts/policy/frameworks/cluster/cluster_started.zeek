# @TEST-DOC: Run a simple cluster to verify cluster_started() and node_fully_connected() are generated.
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 40
# @TEST-EXEC: TEST_DIFF_CANONIFIER=sort btest-diff manager/.stdout

@load policy/frameworks/cluster/experimental

redef Log::default_rotation_interval = 0secs;

event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	print "A) node fully connected", name, resending;
	}

event Cluster::Experimental::cluster_started()
	{
	print "B) Got cluster_started event";
	terminate();
	}
