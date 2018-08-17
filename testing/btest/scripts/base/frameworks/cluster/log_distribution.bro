# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run logger-1 BROPATH=$BROPATH:.. CLUSTER_NODE=logger-1 bro %INPUT
# @TEST-EXEC: btest-bg-run logger-2 BROPATH=$BROPATH:.. CLUSTER_NODE=logger-2 bro %INPUT
# @TEST-EXEC: btest-bg-run manager BROPATH=$BROPATH:.. CLUSTER_NODE=manager bro %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff logger-1/test.log
# @TEST-EXEC: btest-diff logger-2/test.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::manager_is_logger = F;

redef Cluster::nodes = {
    ["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
    ["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=37760/tcp, $manager="manager", $interface="eth0"],
    ["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=37762/tcp, $manager="manager"],
    ["logger-2"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=37763/tcp, $manager="manager"]
};

@TEST-END-FILE

redef Log::default_rotation_interval = 0sec;

module Test;
redef enum Log::ID += { LOG };

type Info: record {
	num: count &log;
};

event bro_init() &priority=5
	{
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);
	}

global peer_count = 0;
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

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	++peer_count;

	if ( Cluster::node == "worker-1" && peer_count == 3 )
		{
		Cluster::logger_pool$rr_key_seq["Cluster::rr_log_topic"] = 0;
		schedule 0.25sec { do_count() };
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node_down", name;
	--peer_count;

	if ( name == "worker-1" )
		schedule 2sec { go_away() };
	}

