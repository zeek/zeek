# @TEST-DOC: Regression test for unsubscriptions not actually unsubscribing because of "\x00" usage.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only ./manager.zeek ./worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global start_test: event() &is_used;

# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event Cluster::Backend::ZeroMQ::subscription(topic: string) {
	if ( topic == "/test/worker/topic" ) {
		print "subscription", topic;
		Cluster::subscribe("/test/manager/topic");
	}
}

event Cluster::Backend::ZeroMQ::unsubscription(topic: string) {
	if ( topic == "/test/worker/topic" ) {
		print "unsubscription", topic;
		Cluster::unsubscribe("/test/manager/topic");
	}
}

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), start_test);
}

event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event start_test() {
	print "start_test";
	Cluster::subscribe("/test/worker/topic");
}

event Cluster::Backend::ZeroMQ::subscription(topic: string) {
	if ( topic == "/test/manager/topic" ) {
		print "subscription", topic;
		Cluster::unsubscribe("/test/worker/topic");
	}
}

event Cluster::Backend::ZeroMQ::unsubscription(topic: string) {
	if ( topic == "/test/manager/topic" ) {
		print "unsubscription", topic;
		terminate();
	}
}

event zeek_done() {
	print "done";
}
# @TEST-END-FILE
