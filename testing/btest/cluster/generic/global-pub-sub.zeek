# @TEST-DOC: Test global publish/subscribe visiblitiy with Broker and ZeroMQ.
#
# This test starts a cluster with every node subscribing to
# "zeek.cluster.all", waits for the cluster to be up, then
#
#  1) worker-1 publishes to zeek.cluster.all
#  2) proxy-1 publishes to zeek.cluster.all
#  3) logger-1 publishes to zeek.cluster.all
#  4) manager publishes to zeek.cluster.all
#
#  5) All nodes terminate when receiving the manager's message,
#  6) The manager terminates after it observed Cluster::node_down()
#     from all other nodes.
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT5
# @TEST-PORT: BROKER_PORT6
# @TEST-PORT: BROKER_PORT7
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT_1
#
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run zeromq-manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-logger-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-logger-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-2 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-proxy-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-proxy-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-run zeromq-worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT ../zeromq.zeek
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-logger-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-logger-2/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-proxy-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-proxy-2/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeromq-worker-2/.stdout
#
# @TEST-EXEC: btest-bg-run broker-logger-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-2 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-logger-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-proxy-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-proxy-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-run broker-worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT ../broker.zeek
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-logger-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-logger-2/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-proxy-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-proxy-2/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff broker-worker-2/.stdout


@load policy/frameworks/cluster/experimental

const global_topic = "zeek.cluster.all";

@TEST-START-FILE cluster-layout.zeek
redef Cluster::manager_is_logger = F;

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager"],
	["logger-2"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager"],
	["proxy-1"] = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager"],
	["proxy-2"] = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT5")), $manager="manager"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT6")), $manager="manager"],
	["worker-2"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT7")), $manager="manager"],
};
@TEST-END-FILE

event Cluster::node_up(name: string, id: string)
	{
	print "B node_up", name;
	}

event test_event(msg: string) {
	print "D test_event", msg;

	if ( Cluster::node == "proxy-1" && msg == "from-worker-1")
		Cluster::publish(global_topic, test_event, "x-from-proxy-1");

	if ( Cluster::node == "logger-1" && msg == "x-from-proxy-1")
		Cluster::publish(global_topic, test_event, "y-from-logger-1");

	if ( Cluster::node == "manager" && msg == "y-from-logger-1")
		Cluster::publish(global_topic, test_event, "z-from-manager");

	if ( msg == "z-from-manager") {
		print "Z terminate after manager message";
		terminate();
	}
}

event go()
	{
	if ( Cluster::node == "worker-1" )
		Cluster::publish(global_topic, test_event, "from-worker-1");
	}

event Cluster::Experimental::cluster_started()
	{
	print "C cluster_started";

	if ( Cluster::node == "worker-1" )
		{
		## XXX: Subscriptions for broker apparently aren't fully
		##      ready at cluster_started() time yet. The observation
		##      is that various nodes miss messages if this delay is
		##      removed.
		##
		##	Not sure what's going on here.
		if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
			schedule 1000msec { go() };
		else
			event go();
		}
	}

@if ( Cluster::node == "manager" )

global nodes_down = 0;

# If the manager saw all nodes down, terminate it.
event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	if ( nodes_down >= |Cluster::nodes| - 1 )
		{
		print "Z all nodes down";
		terminate();
		}
	}
@endif

event zeek_init() {
	print Cluster::node;
	Cluster::subscribe(global_topic);
}

@TEST-START-FILE broker.zeek
redef Cluster::enable_global_pub_sub = T;
@TEST-END-FILE

@TEST-START-FILE zeromq.zeek
@load ./zeromq-test-bootstrap.zeek
@TEST-END-FILE
