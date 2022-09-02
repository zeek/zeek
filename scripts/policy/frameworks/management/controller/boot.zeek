##! The cluster controller's boot logic runs in Zeek's supervisor and instructs
##! it to launch the Management controller process. The controller's main logic
##! resides in main.zeek, similarly to other frameworks. The new process will
##! execute that script.
##!
##! If the current process is not the Zeek supervisor, this does nothing.

@load base/utils/paths

@load ./config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = Management::Controller::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
	    $addl_base_scripts=vector("policy/frameworks/management/controller/main.zeek"));

	# Establish the controller's working directory. If one is configured
	# explicitly, use as-is if absolute. Otherwise, append it to the state
	# path. Without an explicit directory, fall back to the agent name.
	local statedir = build_path(Management::get_state_dir(), "nodes");

	if ( ! mkdir(statedir) )
		print(fmt("warning: could not create state dir '%s'", statedir));

	if ( Management::Controller::directory != "" )
		sn$directory = build_path(statedir, Management::Controller::directory);
	else
		sn$directory = build_path(statedir, Management::Controller::get_name());

	if ( ! mkdir(sn$directory) )
		print(fmt("warning: could not create controller state dir '%s'", sn$directory));

	# We don't set sn$stdout_file/stderr_file here because the Management
	# framework's Supervisor shim manages those output files itself. See
	# frameworks/management/supervisor/main.zeek for details.

	# This helps identify Management framework nodes reliably.
	sn$env["ZEEK_MANAGEMENT_NODE"] = "CONTROLLER";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
