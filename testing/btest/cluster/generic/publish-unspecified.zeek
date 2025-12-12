# @TEST-DOC: Startup a manager running the ZeroMQ proxy thread, a worker connects and the manager sends a finish event to terminate the worker.
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
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

type ResultTable: table[string] of count;
type ResultSet : set[count];

global ping_table: event(msg: string, t: ResultTable) &is_used;
global pong_table: event(msg: string, t: ResultTable) &is_used;

global ping_set: event(msg: string, s: ResultSet) &is_used;
global pong_set: event(msg: string, s: ResultSet) &is_used;

global finish: event() &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
# If a node comes up that isn't us, send it a finish event.
event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), ping_table, "hello", table());
	Cluster::publish(Cluster::nodeid_topic(id), ping_set, "hello", set());
	}


event pong_table(msg: string, t: ResultTable)
	{
	print "pong_table", msg, type_name(t), cat(t);
	}

event pong_set(msg: string, t: ResultSet)
	{
	print "pong_set", msg, type_name(t), cat(t);
	Cluster::publish(Cluster::worker_topic, finish);
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

event ping_table(msg: string, t: ResultTable) &is_used
	{
	print "ping_table", msg, type_name(t), cat(t);
	local e = Cluster::make_event(pong_table, msg, table());
	Cluster::publish(Cluster::manager_topic, e);
	}

event ping_set(msg: string, t: ResultSet) &is_used
	{
	print "ping_set", msg, type_name(t), cat(t);
	local e = Cluster::make_event(pong_set, msg, set());
	Cluster::publish(Cluster::manager_topic, e);
	}

event finish()
	{
	terminate();
	}
# @TEST-END-FILE
