# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager/notice.log

@load policy/frameworks/cluster/experimental
@load base/frameworks/notice

redef Log::default_rotation_interval = 0secs;

redef enum Notice::Type += {
	Test_Notice,
};

event delayed_notice()
	{
	if ( Cluster::node == "worker-1" )
		NOTICE([$note=Test_Notice, $msg="test notice!"]);
	}

event terminate_me()
	{
	terminate();
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "worker-1" )
		return;

	schedule 1secs { delayed_notice() };
	schedule 2secs { terminate_me() };
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
