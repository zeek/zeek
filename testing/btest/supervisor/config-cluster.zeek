# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: MANAGER_PORT
# @TEST-PORT: LOGGER_PORT
# @TEST-PORT: PROXY_PORT
# @TEST-PORT: WORKER_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff zeek/supervisor.out
# @TEST-EXEC: btest-diff zeek/manager/stdout
# @TEST-EXEC: btest-diff zeek/logger-1/stdout
# @TEST-EXEC: btest-diff zeek/worker-1/stdout
# @TEST-EXEC: btest-diff zeek/proxy-1/stdout

@load policy/frameworks/cluster/experimental

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global supervisor_output_file: file;
global topic = "test-topic";

event shutdown()
	{
	print supervisor_output_file, "shutting down";
	terminate();
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		Broker::subscribe(topic);
		Broker::listen("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		supervisor_output_file = open("supervisor.out");
		print supervisor_output_file, "supervisor zeek_init()";

		local cluster: table[string] of Supervisor::ClusterEndpoint;
		cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1,
			$p=to_port(getenv("MANAGER_PORT"))];
		cluster["logger-1"] = [$role=Supervisor::LOGGER, $host=127.0.0.1,
			$p=to_port(getenv("LOGGER_PORT"))];
		cluster["proxy-1"] = [$role=Supervisor::PROXY, $host=127.0.0.1,
			$p=to_port(getenv("PROXY_PORT"))];
		cluster["worker-1"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
			$p=to_port(getenv("WORKER_PORT"))];

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
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		print "supervised node zeek_init()", Cluster::node, Cluster::local_node_type();
		}
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "manager" )
		Broker::publish(topic, shutdown);
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		print "supervised node zeek_done()", Cluster::node, Supervisor::node()$name;
	else
		print supervisor_output_file, "supervisor zeek_done()";
	}
