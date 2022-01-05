##! Configuration settings for the cluster controller.

@load policy/frameworks/cluster/agent/config

module ClusterController;

export {
	## The name of this controller. Defaults to the value of the
	## ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
	## user doesn't redef the value, the implementation defaults to
	## "controller-<hostname>".
	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;

	## The controller's stdout log name. If the string is non-empty, Zeek will
	## produce a free-form log (i.e., not one governed by Zeek's logging
	## framework) in Zeek's working directory. If left empty, no such log
	## results.
	##
	## Note that the controller also establishes a "proper" Zeek log via the
	## :zeek:see:`ClusterController::Log` module.
	const stdout_file = "controller.stdout" &redef;

	## The controller's stderr log name. Like :zeek:see:`ClusterController::stdout_file`,
	## but for the stderr stream.
	const stderr_file = "controller.stderr" &redef;

	## The network address the controller listens on. By default this uses
	## the value of the ZEEK_CONTROLLER_ADDR environment variable, but you
	## may also redef to a specific value. When empty, the implementation
	## falls back to :zeek:see:`ClusterController::default_address`.
	const listen_address = getenv("ZEEK_CONTROLLER_ADDR") &redef;

	## The fallback listen address if :zeek:see:`ClusterController::listen_address`
	## remains empty. Unless redefined, this uses Broker's own default
	## listen address.
	const default_address = Broker::default_listen_address &redef;

	## The network port the controller listens on. Counterpart to
	## :zeek:see:`ClusterController::listen_address`, defaulting to the
	## ZEEK_CONTROLLER_PORT environment variable.
	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;

	## The fallback listen port if :zeek:see:`ClusterController::listen_port`
	## remains empty.
	const default_port = 2150/tcp &redef;

	## The controller's connect retry interval. Defaults to a more
	## aggressive value compared to Broker's 30s.
	const connect_retry = 1sec &redef;

	## The controller's Broker topic. Clients send requests to this topic.
	const topic = "zeek/cluster-control/controller" &redef;

	## The role of this process in cluster management. Agent and controller
	## both redefine this. Used during logging.
	const role = ClusterController::Types::NONE &redef;

	## The timeout for request state. Such state (see the :zeek:see:`ClusterController::Request`
	## module) ties together request and response event pairs. The timeout causes
	## its cleanup in the absence of a timely response. It applies both to
	## state kept for client requests, as well as state in the agents for
	## requests to the supervisor.
	const request_timeout = 10sec &redef;

	## An optional custom output directory for the controller's stdout and
	## stderr logs. Agent and controller currently only log locally, not via
	## the data cluster's logger node. (This might change in the future.)
	## This means that if both write to the same log file, the output gets
	## garbled.
	const directory = "" &redef;

	## Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.
	global network_info: function(): Broker::NetworkInfo;

	## Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.
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
