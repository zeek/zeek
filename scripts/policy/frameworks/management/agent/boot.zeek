##! The cluster agent boot logic runs in Zeek's supervisor and instructs it to
##! launch a Management agent process. The agent's main logic resides in main.zeek,
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

	local epi = Management::Agent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
		$scripts=vector("policy/frameworks/management/agent/main.zeek"));

	if ( Management::Agent::directory != "" )
		sn$directory = Management::Agent::directory;
	if ( Management::Agent::stdout_file != "" )
		sn$stdout_file = Management::Agent::stdout_file;
	if ( Management::Agent::stderr_file != "" )
		sn$stderr_file = Management::Agent::stderr_file;

	# This helps identify Management framework nodes reliably.
	sn$env["ZEEK_MANAGEMENT_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
