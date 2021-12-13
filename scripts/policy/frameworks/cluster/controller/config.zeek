@load policy/frameworks/cluster/agent/config

module ClusterController;

export {
	# The name of this controller in the cluster.
	# Without the environment variable and no redef, this
	# falls back to "controller-<hostname>".
	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;

	# Controller stdout/stderr log files to produce in Zeek's
	# working directory. If empty, no such logs will result.
	const stdout_file = "controller.stdout" &redef;
	const stderr_file = "controller.stderr" &redef;

	# The address and port the controller listens on. When
	# undefined, falls back to the default_address, which you can
	# likewise customize.
	const listen_address = getenv("ZEEK_CONTROLLER_ADDR") &redef;
	const default_address = Broker::default_listen_address &redef;

	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;
	const default_port = 2150/tcp &redef;

	# A more aggressive default retry interval (vs default 30s)
	const connect_retry = 1sec &redef;

	# The controller listens for messages on this topic:
	const topic = "zeek/cluster-control/controller" &redef;

	# The role of this node in cluster management. Agent and
	# controller both redef this. Used during logging.
	const role = ClusterController::Types::NONE &redef;

	# The timeout for client request state.
	const request_timeout = 15sec &redef;

	# Agent and controller currently log only, not via the data cluster's
	# logger. (This might get added later.) For now, this means that
	# if both write to the same log file, it gets garbled. The following
	# lets you specify the working directory specifically for the agent.
	const directory = "" &redef;

	# The following functions return the effective network endpoint
	# information for this controller, in two related forms.
	global network_info: function(): Broker::NetworkInfo;
	global endpoint_info: function(): Broker::EndpointInfo;
}

function network_info(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( ClusterController::listen_address != "" )
		ni$address = ClusterController::listen_address;
	else if ( ClusterController::default_address != "" )
		ni$address = ClusterController::default_address;
	else
		ni$address = "127.0.0.1";

	if ( ClusterController::listen_port != "" )
		ni$bound_port = to_port(ClusterController::listen_port);
	else
		ni$bound_port = ClusterController::default_port;

	return ni;
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	if ( ClusterController::name != "" )
		epi$id = ClusterController::name;
	else
		epi$id = fmt("controller-%s", gethostname());

	epi$network = network_info();

	return epi;
	}
