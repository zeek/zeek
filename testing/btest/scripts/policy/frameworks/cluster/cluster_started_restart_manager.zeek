# @TEST-DOC: Verify cluster_started() is not rebroadcasted if the manager restarts.
# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: MANAGER_PORT
# @TEST-PORT: PROXY_PORT
# @TEST-PORT: WORKER1_PORT
# @TEST-PORT: WORKER2_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 25
# @TEST-EXEC: btest-diff zeek/supervisor.out
# @TEST-EXEC: btest-diff zeek/manager/stdout
# @TEST-EXEC: btest-diff zeek/worker-1/stdout
# @TEST-EXEC: btest-diff zeek/proxy-1/stdout

@load policy/frameworks/cluster/experimental

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

redef Log::default_rotation_interval = 0secs;

global topic = "test-topic";

@if ( Supervisor::is_supervisor() )

global supervisor_output_file: file;
global manager_starts = 0;

event Cluster::Experimental::cluster_started()
	{
	# Restart the manager a first time
	++manager_starts;
	print supervisor_output_file, "restarting manager";
	Supervisor::restart("manager");
	}

global redispatched_signals = 0;

event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	if ( resending )
		++redispatched_signals;

	if ( redispatched_signals == 3 )
		{
		# Restart the manager a second time
		if ( ++manager_starts >= 3 )
			{
			terminate();
			return;
			}

		print supervisor_output_file, "restarting manager";
		Supervisor::restart("manager");
		redispatched_signals = 0;
		}
	}

event zeek_init()
	{
	Broker::subscribe(topic);
	Broker::listen("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
	supervisor_output_file = open("supervisor.out");
	print supervisor_output_file, "supervisor zeek_init()";

	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1,
		$p=to_port(getenv("MANAGER_PORT"))];
	cluster["proxy-1"] = [$role=Supervisor::PROXY, $host=127.0.0.1,
		$p=to_port(getenv("PROXY_PORT"))];
	cluster["worker-1"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
		$p=to_port(getenv("WORKER1_PORT"))];
	cluster["worker-2"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
		$p=to_port(getenv("WORKER2_PORT"))];

	for ( n, ep in cluster )
		{
		local sn = Supervisor::NodeConfig($name = n);
		sn$cluster = cluster;
		sn$directory = n;
		sn$stdout_file = "stdout";
		sn$stderr_file = "stderr";
		local res = Supervisor::create(sn);

		if ( res != "" )
			print fmt("failed to create node %s: %s", n, res);
		}
	}

event zeek_done()
	{
	print supervisor_output_file, "supervisor zeek_done()";
	}

@else

event zeek_init()
	{
	print "supervised node zeek_init()", Cluster::node;

	Broker::peer("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
	}

event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	print fmt("node fully connected (resending: %s)", resending);
	if ( Cluster::node == "manager" )
		Broker::publish(topic, Cluster::Experimental::node_fully_connected, name, id, resending);
	}

event Cluster::Experimental::cluster_started()
	{
	print "cluster_started";
	if ( Cluster::node == "manager" )
		Broker::publish(topic, Cluster::Experimental::cluster_started);
	}

event zeek_done()
	{
	print "supervised node zeek_done()", Cluster::node;
	}

@endif
