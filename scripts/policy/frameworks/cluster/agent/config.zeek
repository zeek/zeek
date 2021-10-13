@load policy/frameworks/cluster/controller/types

module ClusterAgent;

export {
	# The name this agent uses to represent the cluster instance
        # it manages. When the environment variable isn't set and there's,
	# no redef, this falls back to "agent-<hostname>".
	const name = getenv("ZEEK_AGENT_NAME") &redef;

	# Agent stdout/stderr log files to produce in Zeek's working
	# directory. If empty, no such logs will result. The actual
	# log files have the agent's name (as per above) dot-prefixed.
	const stdout_file_suffix = "agent.stdout" &redef;
	const stderr_file_suffix = "agent.stderr" &redef;

	# The address and port the agent listens on. When
	# undefined, falls back to configurable default values.
	const listen_address = getenv("ZEEK_AGENT_ADDR") &redef;
	const default_address = Broker::default_listen_address &redef;

	const listen_port = getenv("ZEEK_AGENT_PORT") &redef;
	const default_port = 2151/tcp &redef;

	# The agent communicates under to following topic prefix,
	# suffixed with "/<name>" (see above):
	const topic_prefix = "zeek/cluster-control/agent" &redef;

	# The coordinates of the controller. When defined, it means
	# agents peer with (connect to) the controller; otherwise the
	# controller knows all agents and peers with them.
	const controller: Broker::NetworkInfo = [
		$address="0.0.0.0", $bound_port=0/unknown] &redef;

	# Agent and controller currently log only, not via the data cluster's
        # logger. (This might get added later.) For now, this means that
	# if both write to the same log file, it gets garbled. The following
	# lets you specify the working directory specifically for the agent.
	const directory = "" &redef;

	# Working directory for data cluster nodes. When relative, note
	# that this will apply from the working directory of the agent,
	# since it creates data cluster nodes.
	const cluster_directory = "" &redef;

	# The following functions return the effective network endpoint
	# information for this agent, in two related forms.
	global instance: function(): ClusterController::Types::Instance;
	global endpoint_info: function(): Broker::EndpointInfo;
}

function instance(): ClusterController::Types::Instance
	{
	local epi = endpoint_info();
	return ClusterController::Types::Instance($name=epi$id,
		$host=to_addr(epi$network$address),
		$listen_port=epi$network$bound_port);
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;
	local network: Broker::NetworkInfo;

	if ( ClusterAgent::name != "" )
		epi$id = ClusterAgent::name;
	else
		epi$id = fmt("agent-%s", gethostname());

	if ( ClusterAgent::listen_address != "" )
		network$address = ClusterAgent::listen_address;
	else if ( ClusterAgent::default_address != "" )
		network$address = ClusterAgent::default_address;
	else
		network$address = "127.0.0.1";

	if ( ClusterAgent::listen_port != "" )
		network$bound_port = to_port(ClusterAgent::listen_port);
	else
		network$bound_port = ClusterAgent::default_port;

	epi$network = network;

	return epi;
	}
