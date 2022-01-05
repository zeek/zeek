##! Configuration settings for a cluster agent.

@load policy/frameworks/cluster/controller/types

module ClusterAgent;

export {
	## The name this agent uses to represent the cluster instance it
	## manages. Defaults to the value of the ZEEK_AGENT_NAME environment
	## variable. When that is unset and you don't redef the value,
	## the implementation defaults to "agent-<hostname>".
	const name = getenv("ZEEK_AGENT_NAME") &redef;

	## Agent stdout log configuration. If the string is non-empty, Zeek will
	## produce a free-form log (i.e., not one governed by Zeek's logging
	## framework) in Zeek's working directory. The final log's name is
	## "<name>.<suffix>", where the name is taken from :zeek:see:`ClusterAgent::name`,
	## and the suffix is defined by the following variable. If left empty,
	## no such log results.
	##
	## Note that the agent also establishes a "proper" Zeek log via the
	## :zeek:see:`ClusterController::Log` module.
	const stdout_file_suffix = "agent.stdout" &redef;

	## Agent stderr log configuration. Like :zeek:see:`ClusterAgent::stdout_file_suffix`,
	## but for the stderr stream.
	const stderr_file_suffix = "agent.stderr" &redef;

	## The network address the agent listens on. This only takes effect if
	## the agent isn't configured to connect to the controller (see
	## :zeek:see:`ClusterAgent::controller`). By default this uses the value of the
	## ZEEK_AGENT_ADDR environment variable, but you may also redef to
	## a specific value. When empty, the implementation falls back to
	## :zeek:see:`ClusterAgent::default_address`.
	const listen_address = getenv("ZEEK_AGENT_ADDR") &redef;

	## The fallback listen address if :zeek:see:`ClusterAgent::listen_address`
	## remains empty. Unless redefined, this uses Broker's own default listen
	## address.
	const default_address = Broker::default_listen_address &redef;

	## The network port the agent listens on. Counterpart to
	## :zeek:see:`ClusterAgent::listen_address`, defaulting to the ZEEK_AGENT_PORT
	## environment variable.
	const listen_port = getenv("ZEEK_AGENT_PORT") &redef;

	## The fallback listen port if :zeek:see:`ClusterAgent::listen_port` remains empty.
	const default_port = 2151/tcp &redef;

	## The agent's Broker topic prefix. For its own communication, the agent
	## suffixes this with "/<name>", based on :zeek:see:`ClusterAgent::name`.
	const topic_prefix = "zeek/cluster-control/agent" &redef;

	## The network coordinates of the controller. When defined, the agent
	## peers with (and connects to) the controller; otherwise the controller
	## will peer (and connect to) the agent, listening as defined by
	## :zeek:see:`ClusterAgent::listen_address` and :zeek:see:`ClusterAgent::listen_port`.
	const controller: Broker::NetworkInfo = [
		$address="0.0.0.0", $bound_port=0/unknown] &redef;

	## An optional custom output directory for the agent's stdout and stderr
	## logs. Agent and controller currently only log locally, not via the
	## data cluster's logger node. (This might change in the future.) This
	## means that if both write to the same log file, the output gets
	## garbled.
	const directory = "" &redef;

	## The working directory for data cluster nodes created by this
	## agent. If you make this a relative path, note that the path is
	## relative to the agent's working directory, since it creates data
	## cluster nodes.
	const cluster_directory = "" &redef;

	## Returns a :zeek:see:`ClusterController::Types::Instance` describing this
	## instance (its agent name plus listening address/port, as applicable).
	global instance: function(): ClusterController::Types::Instance;

	## Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
	## Similar to :zeek:see:`ClusterAgent::instance`, but with slightly different
	## data format.
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
