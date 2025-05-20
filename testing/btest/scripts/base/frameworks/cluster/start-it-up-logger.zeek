# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_LOGGER1_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run logger-1  CLUSTER_NODE=logger-1  ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-run manager   CLUSTER_NODE=manager   ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   CLUSTER_NODE=proxy-1   ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   CLUSTER_NODE=proxy-2   ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  CLUSTER_NODE=worker-1  ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  CLUSTER_NODE=worker-2  ZEEKPATH=$ZEEKPATH:.. zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 40
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff logger-1/.stdout
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@load base/frameworks/cluster

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
		return;
		}

	local expected_nodes = Cluster::node == "manager" ? 5 : 4;
	if ( peer_count == expected_nodes )
		{
		Broker::publish(Cluster::logger_topic, fully_connected, Cluster::node);
		print "sent fully_connected event";
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
