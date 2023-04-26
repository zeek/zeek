# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
#
# Note: the logger names are chosen on purpose such that one is a prefix of the
# other to help verify that the node-specific Cluster topics are able to
# uniquely target a particular node.
# @TEST-EXEC: btest-bg-run logger-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run logger-10 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-10 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff logger-1/test.log
# @TEST-EXEC: btest-diff logger-10/test.log

@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::manager_is_logger = F;

redef Cluster::nodes = {
    ["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
    ["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager", $interface="eth0"],
    ["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager"],
    ["logger-10"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager"]
};

@TEST-END-FILE

redef Log::default_rotation_interval = 0sec;

module Test;
redef enum Log::ID += { LOG };

type Info: record {
	num: count &log;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);
	}

global c = 0;

event go_away()
	{
	terminate();
	}

event do_count()
	{
	Log::write(Test::LOG, [$num = ++c]);

	if ( c == 100 )
		{
		Broker::flush_logs();
		schedule 2sec { go_away() };
		}
	else
		schedule 0.01sec { do_count() };
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "worker-1" )
		return;

	Cluster::logger_pool$rr_key_seq["Cluster::rr_log_topic"] = 0;
	schedule 0.25sec { do_count() };
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( name == "worker-1" )
		schedule 2sec { go_away() };
	}

