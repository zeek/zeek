# @TEST-DOC: Ensure that worker-1 does not observe messages to worker-20 on its Cluster::node_topic()
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-10 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-10 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-20 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-20 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-2/out
# @TEST-EXEC: btest-diff ./worker-10/out
# @TEST-EXEC: btest-diff ./worker-20/out

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global ping: event(from: string, to: string);
global pong: event(from: string, to: string);
global finish: event(from: string, to: string);

event zeek_init()
	{
	print "A", Cluster::node;
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_down = 0;
global nodes_up = 0;

event send_pings()
	{
	for ( name, n in Cluster::nodes )
		if ( n$node_type == Cluster::WORKER )
			Cluster::publish(Cluster::node_topic(name), ping, Cluster::node, name);
	}

# If a node comes up, send it a ping
event Cluster::node_up(name: string, id: string)
	{
	print fmt("B node_up - sending ping to '%s'", name);
	++nodes_up;

	if ( nodes_up == 4 )
		event send_pings();
	}

event ping(from: string, to: string)
	{
	# manager node should never see ping events.
	print "XXX FAIL ping", from, to;
	}

event pong(from: string, to: string)
	{
	print fmt("C pong from '%s' to '%s'", from ,to);
	Cluster::publish(Cluster::node_topic(from), finish, Cluster::node, from);
	}

# If the worker vanishes, finish the test.
event Cluster::node_down(name: string, id: string)
	{
	print fmt("D node_down from '%s'", name);
	++nodes_down;
	if ( nodes_down == 4 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

# Reply to a ping with a pong.
event ping(from: string, to: string)
	{
	if ( to != Cluster::node )
		print fmt("FAIL: got ping destined to '%s'", to);

	print fmt("B ping from '%s' to '%s'", from, to);
	Cluster::publish(Cluster::node_topic(from), pong, Cluster::node, from);
	}

event finish(from: string, to: string) &is_used
	{
	print fmt("C finish from '%s' to '%s'", from, to);
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::manager_is_logger = T;
redef Log::default_rotation_interval = 0.0sec;

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
	["worker-2"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
	["worker-10"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
	["worker-20"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
};
# @TEST-END-FILE
