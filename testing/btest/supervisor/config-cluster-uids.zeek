# @TEST-DOC: Check that uids differ between nodes in a supervised cluster.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: MANAGER_PORT
# @TEST-PORT: PROXY_PORT
# @TEST-PORT: WORKER1_PORT
# @TEST-PORT: WORKER2_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: zeek-cut uid < zeek/worker-1/conn.log > zeek/w1-uids.log
# @TEST-EXEC: zeek-cut uid < zeek/worker-2/conn.log > zeek/w2-uids.log
# @TEST-EXEC-FAIL: diff zeek/w1-uids.log zeek/w2-uids.log

redef Log::default_rotation_interval = 0sec;
redef Broker::default_port = to_port(getenv("SUPERVISOR_PORT"));

global topic = "test-topic";
global worker_done: event();

@if ( Supervisor::is_supervisor() )

redef SupervisorControl::enable_listen = T;

event zeek_init()
	{
	Broker::subscribe(topic);

	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1,
		$p=to_port(getenv("MANAGER_PORT"))];
	cluster["proxy-1"] = [$role=Supervisor::PROXY, $host=127.0.0.1,
		$p=to_port(getenv("PROXY_PORT"))];
	cluster["worker-1"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
		$p=to_port(getenv("WORKER1_PORT")),
		$pcap_file=(getenv("TRACES") + "/http/206_example_a.pcap")];
	cluster["worker-2"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
		$p=to_port(getenv("WORKER2_PORT")),
		$pcap_file=(getenv("TRACES") + "/http/206_example_b.pcap")];

	for ( n, ep in cluster )
		{
		local sn = Supervisor::NodeConfig($name = n);
		sn$cluster = cluster;
		sn$directory = n;
		sn$stdout_file = "stdout";
		sn$stderr_file = "stderr";

		if ( ep?$pcap_file )
			sn$pcap_file = ep$pcap_file;

		local res = Supervisor::create(sn);

		if ( res != "" )
			print fmt("failed to create node %s: %s", n, res);
		}
	}

global num_worker_done = 0;

event worker_done()
	{
	if ( ++num_worker_done >= Cluster::get_node_count(Cluster::WORKER) )
		terminate();
	}

@else

redef Log::enable_local_logging = T;
redef Log::enable_remote_logging = F;

event zeek_init()
	{
	suspend_processing();
	Broker::peer("127.0.0.1");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( endpoint$network$bound_port == Broker::default_port )
		continue_processing();
	}

event Pcap::file_done(path: string)
	{
	Broker::publish(topic, worker_done);
	}
@endif
