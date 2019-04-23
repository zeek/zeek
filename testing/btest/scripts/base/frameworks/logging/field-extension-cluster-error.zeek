# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager-1 zeek %INPUT"
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek --pseudo-realtime -C -r $TRACES/wikipedia.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: grep qux manager-1/reporter.log   | sed 's#line ..#line XX#g'  > manager-reporter.log
# @TEST-EXEC: grep qux manager-1/reporter-2.log | sed 's#line ..*#line XX#g' >> manager-reporter.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-canonifier | $SCRIPTS/diff-remove-abspath | grep -v ^# | $SCRIPTS/diff-sort" btest-diff manager-reporter.log


@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

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

event kill_worker()
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
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Cluster::node == "manager-1" )
		{
		schedule 2sec { kill_worker() };
		}

	if ( Cluster::node == "worker-1" )
		{
		continue_processing();
		Reporter::info("qux");
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 2sec { die() };
	}
