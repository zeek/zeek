# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 "cp ../cluster-layout.bro . && CLUSTER_NODE=manager-1 bro %INPUT"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run worker-1  "cp ../cluster-layout.bro . && CLUSTER_NODE=worker-1 bro --pseudo-realtime -C -r $TRACES/wikipedia.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: cat manager-1/reporter.log | grep -v "reporter/" > manager-reporter.log
# @TEST-EXEC: btest-diff manager-reporter.log


@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1", $interface="eth0"],
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
	                 $stream      = path,
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
	Broker::publish("death", slow_death);
	}

event bro_init()
	{
	if ( Cluster::node == "worker-1" )
		Broker::subscribe("death");

	if ( Cluster::node == "manager-1" )
		schedule 13sec { kill_worker() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 2sec { die() };
	}
