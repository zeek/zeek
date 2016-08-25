# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run logger-1  CLUSTER_NODE=logger-1 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run manager-1 CLUSTER_NODE=manager-1 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run proxy-1   CLUSTER_NODE=proxy-1 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   CLUSTER_NODE=proxy-2 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  CLUSTER_NODE=worker-1 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  CLUSTER_NODE=worker-2 BROPATH=$BROPATH:.. bro %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff logger-1/.stdout
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.bro
redef Cluster::manager_is_logger = F;
redef Cluster::nodes = {
	["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=37757/tcp],
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37758/tcp, $logger="logger-1", $workers=set("worker-1")],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37759/tcp, $logger="logger-1", $manager="manager-1", $workers=set("worker-1")],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=37760/tcp, $logger="logger-1", $manager="manager-1", $workers=set("worker-2")],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37761/tcp, $logger="logger-1", $manager="manager-1", $proxy="proxy-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37762/tcp, $logger="logger-1", $manager="manager-1", $proxy="proxy-2", $interface="eth1"],
};
@TEST-END-FILE

global fully_connected: event();

global peer_count = 0;

global fully_connected_nodes = 0;

event fully_connected()
	{
	++fully_connected_nodes;
	if ( Cluster::node == "logger-1" )
		{
		if ( peer_count == 5 && fully_connected_nodes == 5 )
			terminate_communication();
		}
	}

redef Cluster::worker2logger_events += /fully_connected/;
redef Cluster::proxy2logger_events += /fully_connected/;
redef Cluster::manager2logger_events += /fully_connected/;

event remote_connection_handshake_done(p: event_peer)
	{
	print "Connected to a peer";
	++peer_count;
	if ( Cluster::node == "logger-1" )
		{
		if ( peer_count == 5 && fully_connected_nodes == 5 )
			terminate_communication();
		}
	else if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 5 )
			event fully_connected();
		}
	else
		{
		if ( peer_count == 3 )
			event fully_connected();
		}
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}
