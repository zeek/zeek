# @TEST-DOC: Testing round-robin of Log::write() across two loggers.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT_1
# @TEST-PORT: LOG_PULL_PORT_2
#
# @TEST-EXEC: chmod +x ./check-log.sh
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-two-loggers.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only common.zeek manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run logger-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger-1 zeek -b ../common.zeek >out"
# @TEST-EXEC: btest-bg-run logger-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger-2 zeek -b ../common.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: test $(grep -c worker-1 logger-1/rr2.log) -gt 10
# @TEST-EXEC: test $(grep -c worker-2 logger-1/rr2.log) -gt 10
# @TEST-EXEC: test $(grep -c worker-1 logger-2/rr2.log) -gt 10
# @TEST-EXEC: test $(grep -c worker-2 logger-2/rr2.log) -gt 10

# @TEST-EXEC: zeek-cut < logger-1/rr2.log > rr2.log
# @TEST-EXEC: zeek-cut < logger-2/rr2.log >> rr2.log
# @TEST-EXEC: sort -n rr2.log > rr2.log.sorted
# @TEST-EXEC: btest-diff rr2.log.sorted

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap.zeek

redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.03sec;
redef Log::write_buffer_size = 7;

module LogRR;

export {
	redef enum Log::ID += { LOG1, LOG2 };
	type Info: record {
		c: count &log;
		from: string &log &default=Cluster::node;
	};

	global go: event();
	global finish: event();
}

event zeek_init()
	{
	Log::create_stream(LOG1, [$columns=Info, $path="rr1"]);
	Log::create_stream(LOG2, [$columns=Info, $path="rr2"]);
	}

event finish()
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event check_ready()
	{
	if ( ! piped_exec("../check-log.sh", "") )
		{
		Reporter::error("check-log.sh failed");
		terminate();
		}

	if ( file_size("DONE") >= 0 )
		{
		Cluster::publish(Cluster::worker_topic, LogRR::go);
		return;
		}

	schedule 0.1sec { check_ready() };
	}

event zeek_init()
	{
	event check_ready();
	}


global nodes_down: set[string];

event Cluster::node_down(name: string, id: string)
	{
	print current_time(), "node_down", name;
	add nodes_down[name];

	if ( |nodes_down| == 2 )  # workers down
		Cluster::publish(Cluster::logger_topic, LogRR::finish);

	if ( |nodes_down| == 4 )  # both loggers down
		terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE worker.zeek
@load ./common.zeek

global do_write2 = F;

event write_log1(c: count)
	{
	if ( do_write2 )
		{
		Log::write(LogRR::LOG1, [$c=10000000]);
		return;
		}

	Log::write(LogRR::LOG1, [$c=c]);
	Log::flush(LogRR::LOG1);
	schedule 0.05sec { write_log1(++c) };
	}

event write_log2(c: count)
	{
	if ( c == 100 )
		{
		terminate();
		return;
		}

	Log::write(LogRR::LOG2, [$c=c]);
	schedule 0.012sec { write_log2(++c) };
	}

event LogRR::go()
	{
	do_write2 = T;
	event write_log2(0);
	}

event zeek_init()
	{
	event write_log1(0);
	}

# @TEST-END-FILE

# @TEST-START-FILE check-log.sh
#!/usr/bin/env bash
#
# This script regularly checks for the loggers rr1.log file until
# both workers appear. Once this happens, creates a READY file
# which will result in workers getting the "go" and sending writes
# to rr2.log
set -eux

LOGGERS="logger-1 logger-2"
WORKERS="worker-1 worker-2"

for logger in $LOGGERS; do
	for worker in $WORKERS; do
		date +%s
		echo check $logger $worker
		if ! grep -q "${worker}" ../${logger}/rr1.log; then
			exit 0
		fi
	done
done

echo "DONE"
echo "DONE" > DONE
exit 0
# @TEST-END-FILE
