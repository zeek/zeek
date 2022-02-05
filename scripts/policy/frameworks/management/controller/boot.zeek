##! The cluster controller's boot logic runs in Zeek's supervisor and instructs
##! it to launch the Management controller process. The controller's main logic
##! resides in main.zeek, similarly to other frameworks. The new process will
##! execute that script.
##!
##! If the current process is not the Zeek supervisor, this does nothing.

@load ./config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = Management::Controller::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
	    $scripts=vector("policy/frameworks/management/controller/main.zeek"));

	if ( Management::Controller::directory != "" )
		sn$directory = Management::Controller::directory;
	if ( Management::Controller::stdout_file != "" )
		sn$stdout_file = Management::Controller::stdout_file;
	if ( Management::Controller::stderr_file != "" )
		sn$stderr_file = Management::Controller::stderr_file;

	# This helps Zeek run controller and agent with a minimal set of scripts.
	sn$env["ZEEK_CLUSTER_MGMT_NODE"] = "CONTROLLER";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
