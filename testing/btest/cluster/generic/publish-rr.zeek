# @TEST-DOC: Send ping/pong using publish_rr(), publish() and make_event()
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only common.zeek manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: sort < ./manager/out > ./manager.sorted
# @TEST-EXEC: sort < ./worker-1/out > ./worker-1.sorted
# @TEST-EXEC: sort < ./worker-2/out > ./worker-2.sorted
# @TEST-EXEC: btest-diff manager.sorted
# @TEST-EXEC: btest-diff worker-1.sorted
# @TEST-EXEC: btest-diff worker-2.sorted

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap.zeek

global finish: event();
global ping: event(c: count, how: string);
global pong: event(c: count, how: string, from: string, from_how: string);
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string];
global nodes_down: set[string];
global pongs: set[count, string, string, string];

global i = 0;

event send_rr()
	{
	if (i >= 10 )
		return;

	Cluster::publish_rr(Cluster::worker_pool, "ping-key-args", ping, i, "args");
	local e = Cluster::make_event(ping, i, "make_event");
	Cluster::publish_rr(Cluster::worker_pool, "ping-key-event", e);
	++i;

	schedule 0.01sec { send_rr() };
	}

event pong(c: count, how: string, from: string, from_how: string)
	{
	print "got pong", c, how, from, from_how;
	add pongs[c, how, from, from_how];

	if ( |pongs| == 40 )
		{
		print "have 40, finish!";
		Cluster::publish(Cluster::worker_topic, finish);
		}
	}

event Cluster::node_up(name: string, id: string) {
	add nodes_up[name];
	if ( |nodes_up| == 2 ) {
		event send_rr();
	}
}

event Cluster::node_down(name: string, id: string) {
	add nodes_down[name];
	if ( |nodes_down| == 2 )
		terminate();
}
# @TEST-END-FILE


# @TEST-START-FILE worker.zeek
@load ./common.zeek

event ping(c: count, how: string) {
	print "got ping", c, how;
	Cluster::publish(Cluster::manager_topic, pong, c, how, Cluster::node, "args");
	local e = Cluster::make_event(pong, c, how, Cluster::node, "make_event");
	Cluster::publish(Cluster::manager_topic, e);
}

event Cluster::node_up(name: string, id: string) {
	print "a node_up", name;
}

event finish() &is_used {
	print "z got finish!";
	terminate();
}
# @TEST-END-FILE
