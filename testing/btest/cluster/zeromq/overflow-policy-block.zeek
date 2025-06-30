# @TEST-DOC: Workers and proxy publish to the manager topic. They publish so fast that their XPUB socket blocks. Check that all messages make it through and that the blocks metric is incremented.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only other.zeek
#
# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager  zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy    "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy    zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager/out
# @TEST-EXEC: btest-diff proxy/out
# @TEST-EXEC: btest-diff worker-1/out
# @TEST-EXEC: btest-diff worker-2/out

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global start: event();
global finish: event(name: string);
global ping: event(sender: string, c: count);

# Lower high watermarks from 1000 (default) to something much lower to provoke blocking.
redef Cluster::Backend::ZeroMQ::xpub_sndhwm = 20;
redef Cluster::Backend::ZeroMQ::xsub_rcvhwm = 20;

const total_publishes = 50000;

function get_zeromq_blocks(): count {
	local ms = Telemetry::collect_metrics("zeek", "cluster_zeromq_xpub_blocks_total");
	assert |ms| == 1, fmt("%s", |ms|);
	return double_to_count(ms[0]$value);
}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = {"manager"};
global nodes_down: set[string] = {"manager"};

event send_finish() {
	for ( n in nodes_up )
		Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
}

event Cluster::node_up(name: string, id: string) {
	add nodes_up[name];
	print "B nodes_up", |nodes_up|;

	if ( |nodes_up| == 4 ) {
		Cluster::publish(Cluster::worker_topic, start);
		Cluster::publish(Cluster::proxy_topic, start);
	}
}

event Cluster::node_down(name: string, id: string) {
	add nodes_down[name];
	print "nodes_down", |nodes_down|;
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
}

global last_c: table[string] of count;
global drop_c: table[string] of count;

event zeek_init() {
	for ( name, _ in Cluster::nodes ) {
		if ( name == "manager" )
			next;

		last_c[name] = 0;
		drop_c[name] = 0;
	}
}
event ping(sender: string, c: count) {
	local dropped = c  - last_c[sender] - 1;
	if ( dropped > 0 ) {
		print "DROP", sender, c, last_c[sender], dropped;
		drop_c[sender] += dropped;
	}

	last_c[sender] = c;

	# Check if all senders sent enough messages
	for ( _, lc in last_c )
		if ( lc < total_publishes )
			return;

	event send_finish();
}

event zeek_done() {
	print "drop_c", drop_c;
	print "last_c", last_c;

	local blocks = get_zeromq_blocks();
	if ( blocks == 0 )
		print "GOOD: Observed no XPUB blocks on manager";
	else
		print "FAIL: XPUB blocks on manager";
}
# @TEST-END-FILE


# @TEST-START-FILE other.zeek
@load ./common.zeek

global publishes = 0;
const batch = 100;

event tick() {
	local i = batch;
	while ( i > 0 ) {
		--i;
		++publishes;
		Cluster::publish(Cluster::manager_topic, ping, Cluster::node, publishes);

		if ( publishes >= total_publishes )
			return;
	}

	schedule 0.01msec { tick() };
}

event start() {
	print "start", current_time();
	event tick();
}

event finish(name: string) {
	terminate();
}

event zeek_done() {
	print "zeek_done", current_time();
	local blocks = get_zeromq_blocks();
	if ( blocks > 0 )
		print "GOOD: Observed XPUB blocks";
	else
		print "FAIL: No XPUB blocks";
}
# @TEST-END-FILE
