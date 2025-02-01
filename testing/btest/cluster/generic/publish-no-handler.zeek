# @TEST-DOC: A worker receiving an event without a handler implemented would produce a reporter error
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
# @TEST-EXEC: zeek --parse-only manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./worker/out
# @TEST-EXEC: btest-diff ./worker/.stderr


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap


global hello: event() &is_used;
global finish: event() &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
event send_finish(id: string)
	{
	Cluster::publish(Cluster::nodeid_topic(id), finish);
	}
# If a node comes up that isn't us, send it a hello and
# schedule sending a my_finish
event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), hello);
	schedule 20msec { send_finish(id) };
	}

# If the worker vanishes, finish the test.
event Cluster::node_down(name: string, id: string)
	{
	print "node_down", name;
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek
# The worker does not implement hello!

event finish()
	{
	print "got finish";
	terminate();
	}
# @TEST-END-FILE
