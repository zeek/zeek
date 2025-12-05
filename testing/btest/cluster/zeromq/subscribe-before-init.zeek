# @TEST-DOC: Regression test Cluster::subscribe() blocking if called in a high-priority zeek_init() handler
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
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

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global test: event(c: count) &is_used;

# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event zeek_init() &priority=1000000
	{
	Cluster::subscribe("test.early");
	}

event test(c: count)
	{
	print "test()", c;
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
event Cluster::node_up(name: string, id: string)
	{
	Cluster::publish("test.early", test, 42);
	terminate();
	}
# @TEST-END-FILE
