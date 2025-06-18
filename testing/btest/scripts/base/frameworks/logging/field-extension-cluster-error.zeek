# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek -b --pseudo-realtime -C -r $TRACES/wikipedia.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: grep qux manager/reporter.log   | sed 's#line ..#line XX#g'  > manager-reporter.log
# @TEST-EXEC: grep qux manager/reporter-2.log | sed 's#line ..*#line XX#g' >> manager-reporter.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-remove-abspath | grep -v ^# | $SCRIPTS/diff-sort" btest-diff manager-reporter.log

@load base/frameworks/cluster
@load base/frameworks/logging
@load base/frameworks/reporter
@load base/protocols/conn

@if ( Cluster::node == "worker-1" )
redef exit_only_after_terminate = T;
@endif

redef Log::default_rotation_interval = 0secs;

redef Log::default_scope_sep="_";

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	system_name: string &log;
};

@if ( Cluster::local_node_type() == Cluster::MANAGER )

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = "bah",
	                 $system_name = peer_description);
	}

redef Log::default_ext_func = add_extension;

@endif

event die()
	{
	terminate();
	}

event slow_death()
	{
	Broker::flush_logs();
	schedule 2sec { die() };
	}

event ready()
	{
	Reporter::info("qux");
	Broker::publish("death", slow_death);
	}

event zeek_init()
	{
	if ( Cluster::node == "worker-1" )
		{
		Broker::subscribe("death");
		suspend_processing();
		}

	if ( Cluster::node == "manager" )
		{
		Broker::subscribe("ready");
		}
	}

global conn_count = 0;

event new_connection(c: connection)
	{
	++conn_count;

	if ( conn_count == 30 )
		{
		Reporter::info("qux");
		Broker::publish("ready", ready);
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Cluster::node == "worker-1" )
		continue_processing();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 2sec { die() };
	}
