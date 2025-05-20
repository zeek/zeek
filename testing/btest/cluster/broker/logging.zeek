# @TEST-DOC: Startup a Broker cluster by hand, testing basic logging and node_up and node_down events on the manager.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_LOGGER1_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: chmod +x ./check-test-log.sh
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run logger-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run proxy-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff test.log.normalized
# @TEST-EXEC: sort manager/out > manager.out
# @TEST-EXEC: btest-diff manager.out

# @TEST-START-FILE common.zeek
@load frameworks/cluster/experimental

redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.01sec;

type Info: record {
	self: string &log &default=Cluster::node;
	c: count &log;
};

redef enum Log::ID += { TEST_LOG };

global finish: event(name: string) &is_used;

event zeek_init() {
	print "A zeek_init", Cluster::node;
	Log::create_stream(TEST_LOG, [$columns=Info, $path="test"]);
}

const to_write = 33;
global write = 0;

event tick()
	{
	++write;
	Log::write(TEST_LOG, [$c=write]);
	if ( write < to_write )
		schedule 0.05sec { tick() };
	}

event Cluster::Experimental::cluster_started()
	{
	print "C cluster_started";
	schedule 0.05sec { tick() };
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = {"manager"};
global nodes_down: set[string] = {"manager"};

event send_finish() {
	print "D send_finish";
	for ( n in nodes_up )
		Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
}

event check_test_log() {
	if ( file_size("DONE") >= 0 ) {
		event send_finish();
		return;
	}

	system("../check-test-log.sh");
	schedule 0.1sec { check_test_log() };
}

event zeek_init() {
	schedule 0.1sec { check_test_log() };
}


event Cluster::node_up(name: string, id: string) &priority=-1 {
	add nodes_up[name];
	print "B nodes_up", |nodes_up|;
}

event Cluster::node_down(name: string, id: string) {
	print "E node_down", name;
	add nodes_down[name];
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common.zeek

event finish(name: string) {
	terminate();
}
# @TEST-END-FILE

# @TEST-START-FILE check-test-log.sh
#!/bin/sh
#
# This script checks logger-1/test.log until the expected number
# of log entries have been observed and puts a normalized version
# into the testing directory for baselining.
TEST_LOG=../logger-1/test.log

if [ ! -f $TEST_LOG ]; then
	echo "$TEST_LOG not found!" >&2
	exit 1;
fi

if [ -f DONE ]; then
	exit 0
fi

# Remove hostname and pid from node id in message.
zeek-cut self c < $TEST_LOG | sort > test.log.tmp

# 5 times 33 = 165
if [ $(wc -l < test.log.tmp) = 165 ]; then
	echo "DONE!" >&2
	mv test.log.tmp ../test.log.normalized
	echo "DONE" > DONE
fi

exit 0
# @TEST-END-FILE
