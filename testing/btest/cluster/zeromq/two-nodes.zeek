# @TEST-DOC: Startup a manager running the ZeroMQ proxy thread, a worker connects and the manager sends a finish event to terminate the worker.
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./worker/out


# @TEST-START-FILE common.zeek
@load base/utils/numbers

@load frameworks/cluster/backend/zeromq
@load frameworks/cluster/backend/zeromq/connect

# The manager runs the ZeroMQ proxy thread.
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));

global finish: event(name: string);
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

redef Cluster::node = "manager";
redef Cluster::Backend::ZeroMQ::run_broker_thread = T;

# If a node comes up that isn't us, send it a finish event.
event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
	Cluster::publish(Cluster::nodeid_topic(id), finish, Cluster::node);
}

# If the worker vanishes, finish the test.
event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

redef Cluster::node = "worker-1";

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
}

event finish(name: string) &is_used {
	print fmt("finish from %s", name);
	terminate();
}
# @TEST-END-FILE
