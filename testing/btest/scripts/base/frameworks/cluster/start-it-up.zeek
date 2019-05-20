# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT5
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   BROPATH=$BROPATH:.. CLUSTER_NODE=proxy-2 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT5")), $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

global fully_connected: event();

global peer_count = 0;

global fully_connected_nodes = 0;

event fully_connected()
	{
	if ( ! is_remote_event() )
		return;

	print "Got fully_connected event";
	fully_connected_nodes = fully_connected_nodes + 1;

	if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 4 && fully_connected_nodes == 4 )
			terminate();
		}
	}

event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, fully_connected);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Connected to a peer";
	peer_count = peer_count + 1;

	if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 4 && fully_connected_nodes == 4 )
			terminate();
		}
	else
		{
		if ( peer_count == 3 )
			event fully_connected();
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
