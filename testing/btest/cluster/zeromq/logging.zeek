# @TEST-DOC: Startup a ZeroMQ cluster, testing basic logging and node_up and node_down events.
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run logger "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: zeek-cut -F ' '  < ./logger/node_up.log | sort > test.sorted
# @TEST-EXEC: btest-diff test.sorted

# @TEST-START-FILE common.zeek
@load base/utils/numbers

type Info: record {
	self: string &log &default=Cluster::node;
	node: string &log;
};

redef enum Log::ID += { TEST_LOG };

@load base/frameworks/cluster
@load frameworks/cluster/backend/zeromq
@load frameworks/cluster/backend/zeromq/connect

redef Log::default_rotation_interval = 0sec;

# The manager runs the ZeroMQ proxy thread.
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));

global finish: event(name: string) &is_used;

event zeek_init() {
	print "zeek_init", Cluster::node;
	Log::create_stream(TEST_LOG, [$columns=Info, $path="node_up"]);
}

event Cluster::node_up(name: string, id: string) {
	print "node_up", name;
	Log::write(TEST_LOG, [$node=name]);
}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = {"manager"};
global nodes_down: set[string] = {"manager"};

event send_finish() {
	print "send_finish";

	Log::flush(TEST_LOG);

	# For debugging
	Log::flush(Cluster::LOG);

	for ( n in nodes_up )
		if ( n != "logger" )
			Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
}

event Cluster::node_up(name: string, id: string) {
	add nodes_up[name];
	print "nodes_up", |nodes_up|;

	if ( |nodes_up| == |Cluster::nodes| )
		event send_finish();
}

event Cluster::node_down(name: string, id: string) {
	print "node_down", name;
	add nodes_down[name];

	if ( |nodes_down| == |Cluster::nodes| - 1 ) {
		print "send_finish to logger";
		Cluster::publish(Cluster::node_topic("logger"), finish, Cluster::node);
	}
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
}

# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common.zeek

# If finish is received, shutdown.
event finish(name: string) {
	print fmt("finish from %s", name);
	terminate();
}
# @TEST-END-FILE
