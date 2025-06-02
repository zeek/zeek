# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_LOGGER1_PORT
# @TEST-PORT: BROKER_LOGGER10_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
# Add an additional logger-10 node, the template only has logger-1 and logger-2
# @TEST-EXEC: echo 'redef Cluster::nodes += { ["logger-10"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_LOGGER10_PORT")), $manager="manager"], };' >> cluster-layout.zeek
#
# Note: the logger names are chosen on purpose such that one is a prefix of the
# other to help verify that the node-specific Cluster topics are able to
# uniquely target a particular node.
# @TEST-EXEC: btest-bg-run logger-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run logger-10 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-10 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager   zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1  zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff logger-1/test.log
# @TEST-EXEC: btest-diff logger-10/test.log

@load policy/frameworks/cluster/experimental

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

