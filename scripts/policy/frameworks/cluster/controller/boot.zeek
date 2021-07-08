@load ./config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = ClusterController::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
	    $scripts=vector("policy/frameworks/cluster/controller/main.zeek"));

	if ( ClusterController::directory != "" )
		sn$directory = ClusterController::directory;
	if ( ClusterController::stdout_file != "" )
		sn$stdout_file = ClusterController::stdout_file;
	if ( ClusterController::stderr_file != "" )
		sn$stderr_file = ClusterController::stderr_file;

	# This helps Zeek run controller and agent with a minimal set of scripts.
	sn$env["ZEEK_CLUSTER_MGMT_NODE"] = "CONTROLLER";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
