# @TEST-DOC: Startup a ZeroMQ cluster using ::1 as address. Regression test for #4586
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: can-listen-tcp 6 ::1
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: chmod +x ./check-cluster-log.sh
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# The BTEST_CLUSTER_IP is picked up by cluster-layout-simple.zeek, zeromq-test-bootstrap
# will pickup the manager's IP for rendering XPUB/XSUB listen and connect endpoints.
# @TEST-EXEC: btest-bg-run manager  "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run logger   "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run proxy    "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "BTEST_CLUSTER_IP=::1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff cluster.log.normalized
# @TEST-EXEC: zeek-cut -F ' '  < ./logger/node_up.log | sort > node_up.sorted
# @TEST-EXEC: btest-diff node_up.sorted
# @TEST-EXEC: sort manager/out > manager.out
# @TEST-EXEC: btest-diff manager.out

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.01sec;

type Info: record {
	self: string &log &default=Cluster::node;
	node: string &log;
};

redef enum Log::ID += { TEST_LOG };

global finish: event(name: string) &is_used;

event zeek_init() {
	print "A zeek_init", Cluster::node;
	Log::create_stream(TEST_LOG, [$columns=Info, $path="node_up"]);
}

event Cluster::node_up(name: string, id: string) &priority=-5 {
	print "B node_up", name;
	Log::write(TEST_LOG, [$node=name]);
}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = {"manager"};
global nodes_down: set[string] = {"manager"};

event send_finish() {
	print "C send_finish";
	for ( n in nodes_up )
		if ( n != "logger" )
			Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
}

event check_cluster_log() {
	if ( file_size("DONE") >= 0 ) {
		event send_finish();
		return;
	}

	system("../check-cluster-log.sh");
	schedule 0.1sec { check_cluster_log() };
}

event zeek_init() {
	schedule 0.1sec { check_cluster_log() };
}

event Cluster::node_up(name: string, id: string) &priority=-1 {
	add nodes_up[name];
	print "B nodes_up", |nodes_up|;
}

event Cluster::node_down(name: string, id: string) {
	print "D node_down", name;
	add nodes_down[name];

	if ( |nodes_down| == |Cluster::nodes| - 1 ) {
		print "D send_finish to logger";
		Cluster::publish(Cluster::node_topic("logger"), finish, Cluster::node);
	}
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common.zeek

event finish(name: string) {
	print fmt("finish from %s", name);
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE check-cluster-log.sh
#!/bin/sh
#
# This script checks logger/cluster.log until the expected number
# of log entries have been observed and puts a normalized version
# into the testing directory for baselining.
CLUSTER_LOG=../logger/cluster.log

if [ ! -f $CLUSTER_LOG ]; then
	echo "$CLUSTER_LOG not found!" >&2
	exit 1;
fi

if [ -f DONE ]; then
	exit 0
fi

# Remove hostname and pid from node id in message.
zeek-cut node message < $CLUSTER_LOG | sed -r 's/_[^_]+_[0-9]+_/_<hostname>_<pid>_/g' | sort > cluster.log.tmp

# 4 times 5
if [ $(wc -l < cluster.log.tmp) = 20 ]; then
	echo "DONE!" >&2
	mv cluster.log.tmp ../cluster.log.normalized
	echo "DONE" > DONE
fi

exit 0
# @TEST-END-FILE
