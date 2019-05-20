# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT5
# @TEST-PORT: BROKER_PORT6
#
# @TEST-EXEC: btest-bg-run logger-1  CLUSTER_NODE=logger-1  BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-run manager-1 CLUSTER_NODE=manager-1 BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   CLUSTER_NODE=proxy-1   BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   CLUSTER_NODE=proxy-2   BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  CLUSTER_NODE=worker-1  BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  CLUSTER_NODE=worker-2  BROPATH=$BROPATH:.. zeek %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff logger-1/.stdout
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::manager_is_logger = F;
redef Cluster::nodes = {
	["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT5")), $manager="manager-1", $interface="eth0"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT6")), $manager="manager-1", $interface="eth1"],
};
@TEST-END-FILE

global peer_count = 0;

global fully_connected_nodes = 0;

event fully_connected(n: string)
	{
	++fully_connected_nodes;

	if ( Cluster::node == "logger-1" )
		{
		print "got fully_connected event from", n;

		if ( peer_count == 5 && fully_connected_nodes == 5 )
			{
			print "termination condition met: shutting down";
			terminate();
			}
		}
	else
		{
		print "sent fully_connected event";
		}
	}

event zeek_init()
	{
	Broker::auto_publish(Cluster::logger_topic, fully_connected);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Connected to a peer";
	++peer_count;

	if ( Cluster::node == "logger-1" )
		{
		if ( peer_count == 5 && fully_connected_nodes == 5 )
			{
			print "termination condition met: shutting down";
			terminate();
			}
		}
	else if ( Cluster::node == "manager-1" )
		{
		if ( peer_count == 5 )
			event fully_connected(Cluster::node);
		}
	else
		{
		if ( peer_count == 4 )
			event fully_connected(Cluster::node);
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
