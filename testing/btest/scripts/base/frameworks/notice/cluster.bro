# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/notice.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=27757/tcp, $workers=set("worker-1")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=27758/tcp, $manager="manager-1", $workers=set("worker-1")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=27760/tcp, $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef enum Notice::Type += {
	Test_Notice,
};

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

global ready: event();

redef Cluster::manager2worker_events += /ready/;

event delayed_notice()
	{
	if ( Cluster::node == "worker-1" )
		NOTICE([$note=Test_Notice, $msg="test notice!"]);
	}

@if ( Cluster::local_node_type() == Cluster::WORKER )

event ready()
	{
	schedule 1secs { delayed_notice() };
	}

@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;

event remote_connection_handshake_done(p: event_peer)
	{
	peer_count = peer_count + 1;
	if ( peer_count == 2 )
		event ready();
	}

event Notice::log_notice(rec: Notice::Info)
	{
	terminate_communication();
	}

@endif
