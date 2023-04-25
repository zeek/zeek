# @TEST-DOC: Test support for pcap_file on Supervisor::ClusterEndpoint and Supervisor::NodeConfig
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-PORT: MANAGER_PORT
# @TEST-PORT: WORKER_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: mv zeek/worker/conn.log zeek/worker/conn.log.orig
# @TEST-EXEC: zeek-cut ts uid id.orig_h id.resp_h history service < zeek/worker/conn.log.orig > zeek/worker/conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff zeek/worker/conn.log

redef Log::default_rotation_interval = 0sec;

@if ( Supervisor::is_supervisor() )

redef SupervisorControl::enable_listen = T;

event zeek_init()
	{
	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1,
		$p=to_port(getenv("MANAGER_PORT"))];
	cluster["worker"] = [$role=Supervisor::WORKER, $host=127.0.0.1,
		$p=to_port(getenv("WORKER_PORT")),
		$pcap_file=(getenv("TRACES") + "/wikipedia.trace")];

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

global ready_for_shutdown = F;

# Immediately terminate the supervisor once we get a report about the worker
# starting for a second time.
event Supervisor::node_status(node: string, pid: count)
	{
	if ( node != "worker" )
		return;

	if ( ready_for_shutdown )
		terminate();

	ready_for_shutdown = T;
	}

@else

redef Log::enable_local_logging = T;
redef Log::enable_remote_logging = F;

# Even though we run with a pcap_file, we will not terminate
# once fully read, trigger terminate() directly.
event Pcap::file_done(path: string)
	{
	terminate();
	}
@endif
