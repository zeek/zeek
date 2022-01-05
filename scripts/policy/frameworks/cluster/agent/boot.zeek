##! The cluster agent boot logic runs in Zeek's supervisor and instructs it to
##! launch an agent process. The agent's main logic resides in main.zeek,
##! similarly to other frameworks. The new process will execute that script.
##!
##! If the current process is not the Zeek supervisor, this does nothing.

@load ./config

# The agent needs the supervisor to listen for node management requests.  We
# need to tell it to do so, and we need to do so here, in the agent
# bootstrapping code, so the redef applies prior to the fork of the agent
# process itself.
redef SupervisorControl::enable_listen = T;

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = ClusterAgent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
		$scripts=vector("policy/frameworks/cluster/agent/main.zeek"));

	if ( ClusterAgent::directory != "" )
		sn$directory = ClusterAgent::directory;
	if ( ClusterAgent::stdout_file_suffix != "" )
		sn$stdout_file = epi$id + "." + ClusterAgent::stdout_file_suffix;
	if ( ClusterAgent::stderr_file_suffix != "" )
		sn$stderr_file = epi$id + "." + ClusterAgent::stderr_file_suffix;

	# This helps Zeek run controller and agent with a minimal set of scripts.
	sn$env["ZEEK_CLUSTER_MGMT_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
