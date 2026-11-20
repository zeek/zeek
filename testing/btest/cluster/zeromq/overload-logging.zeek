# @TEST-DOC: Lower the logging high watermarks drastically and observe metrics as well as output on stderr that indicates dropped logs. Tha manager acts as the logger in this test.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: ! is-windows-ci
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: chmod +x ./check-test-log.sh
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
# @TEST-EXEC: cp $FILES/zeromq/metrics.zeek zeromq-metrics.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy zeek -b ../other.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek"
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff proxy/.stderr
# @TEST-EXEC: btest-diff worker-1/.stderr
# @TEST-EXEC: btest-diff worker-2/.stderr
#
# Ensure the manager saw logs from all of the nodes. Nodes only terminate
# once this holds, see the check-test-log.sh script and finish() event.
#
# @TEST-EXEC: zeek-cut node < manager/test.log | sort | uniq > nodes
# @TEST-EXEC: btest-diff nodes

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap
@load ./zeromq-metrics

@load frameworks/cluster/experimental

redef Log::default_rotation_interval = 0sec;

# Default is write_buffer_size=1000 and log_sndhwm=1000 for buffering
# up to 1 million log messages on one node in a cluster. Lower both
# settings such that it's a total of 3 * 3 = 9 messages only. The
# processes log 5 logs every 0.1 msec, so around 50k log records per
# second.
#
# Increasing log_sndhwm to 10 makes the test unreliable on my local
# system, so that's good, but also means this is a bit magic.
redef Log::write_buffer_size = 3;
redef Cluster::Backend::ZeroMQ::log_sndhwm = 3;

# Helpers to get drop counts.
global log_push_drops: function(): count = Cluster::Backend::ZeroMQ::log_push_drops;


redef enum Log::ID += { TEST_LOG };

type Info: record {
	ts: time &log &default=network_time();
	i: count &log;
	node: string &log &default=Cluster::node;
};

# Manager sends this once it saw log records from all nodes.
global finish: event(name: string) &is_used;

event zeek_init()
	{
	print "A zeek_init", Cluster::node;
	Log::create_stream(TEST_LOG, [$columns=Info, $path="test"]);
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = {};
global nodes_down: set[string] = {};

event send_finish()
	{
	print "send_finish()";
	for ( n in nodes_up )
		Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
	}

# Event to regularly invoke check-test-log.sh for scanning through test.log
# until that script has placed a DONE file when log records from all nodes
# have arrived.
event check_test_log()
	{
	if ( file_size("DONE") >= 0 )
		{
		event send_finish();
		return;
		}

	system("../check-test-log.sh");
	schedule 0.025sec { check_test_log() };
	}

event zeek_init()
	{
	schedule 0.025sec { check_test_log() };
	}

event Cluster::node_up(name: string, id: string)
	{
	add nodes_up[name];
	print "nodes_up", |nodes_up|;
	}

event Cluster::node_down(name: string, id: string)
	{
	add nodes_down[name];
	print "nodes_down", |nodes_down|;

	if ( |nodes_down| == |Cluster::nodes| - 1 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common.zeek

global finished = F;

event finish(name: string)
	{
	print "got finish()";
	finished = T;
	}

# How many writes in one tick?
global batch = 7;

event tick()
	{
	local i = batch;

	while ( i > 0 )
		{
		--i;
		Log::write(TEST_LOG, Info($i=i));
		}

	# Check for drops.
	if ( log_push_drops() >= 2 && finished )
		{
		print "had some drops!";
		terminate();
		return;
		}

	schedule 0.01msec { tick() };
	}

event Cluster::Experimental::cluster_started()
	{
	# Start logging once the whole cluster is up.
	event tick();
	}
# @TEST-END-FILE

# @TEST-START-FILE check-test-log.sh
#!/bin/sh
#
# This script checks manager/test.log until at least one log entry from
# all other nodes has arrived.
TEST_LOG=test.log

if [ ! -f $TEST_LOG ]; then
	echo "$TEST_LOG not found!" >&2
	exit 1;
fi

if [ -f DONE ]; then
	exit 0
fi

# Count the individual node names, expecting proxy, worker-1, worker-2.
NODES=$(zeek-cut node < $TEST_LOG | sort | uniq | wc -l)

if [ "$NODES" -eq 3 ]; then
	echo "DONE!" >&2
	echo "DONE" > DONE
fi

exit 0
# @TEST-END-FILE
