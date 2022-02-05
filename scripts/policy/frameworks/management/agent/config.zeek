##! Configuration settings for a cluster agent.

@load policy/frameworks/management/config
@load policy/frameworks/management/types

module Management::Agent;

export {
	## The name this agent uses to represent the cluster instance it
	## manages. Defaults to the value of the ZEEK_AGENT_NAME environment
	## variable. When that is unset and you don't redef the value,
	## the implementation defaults to "agent-<hostname>".
	const name = getenv("ZEEK_AGENT_NAME") &redef;

	## Agent stdout log configuration. If the string is non-empty, Zeek will
	## produce a free-form log (i.e., not one governed by Zeek's logging
	## framework) in Zeek's working directory. The final log's name is
	## "<name>.<suffix>", where the name is taken from :zeek:see:`Management::Agent::name`,
	## and the suffix is defined by the following variable. If left empty,
	## no such log results.
	##
	## Note that the agent also establishes a "proper" Zeek log via the
	## :zeek:see:`Management::Log` module.
	const stdout_file_suffix = "agent.stdout" &redef;

	## Agent stderr log configuration. Like :zeek:see:`Management::Agent::stdout_file_suffix`,
	## but for the stderr stream.
	const stderr_file_suffix = "agent.stderr" &redef;

	## The network address the agent listens on. This only takes effect if
	## the agent isn't configured to connect to the controller (see
	## :zeek:see:`Management::Agent::controller`). By default this uses the value of the
	## ZEEK_AGENT_ADDR environment variable, but you may also redef to
	## a specific value. When empty, the implementation falls back to
	## :zeek:see:`Management::default_address`.
	const listen_address = getenv("ZEEK_AGENT_ADDR") &redef;

	## The network port the agent listens on. Counterpart to
	## :zeek:see:`Management::Agent::listen_address`, defaulting to the ZEEK_AGENT_PORT
	## environment variable.
	const listen_port = getenv("ZEEK_AGENT_PORT") &redef;

	## The fallback listen port if :zeek:see:`Management::Agent::listen_port` remains empty.
	const default_port = 2151/tcp &redef;

	## The agent's Broker topic prefix. For its own communication, the agent
	## suffixes this with "/<name>", based on :zeek:see:`Management::Agent::name`.
	const topic_prefix = "zeek/management/agent" &redef;

	## The network coordinates of the controller. When defined, the agent
	## peers with (and connects to) the controller; otherwise the controller
	## will peer (and connect to) the agent, listening as defined by
	## :zeek:see:`Management::Agent::listen_address` and :zeek:see:`Management::Agent::listen_port`.
	const controller: Broker::NetworkInfo = [
		$address="0.0.0.0", $bound_port=0/unknown] &redef;

	## An optional custom output directory for stdout/stderr. Agent and
	## controller currently only log locally, not via the data cluster's
	## logger node. This means that if both write to the same log file,
	## output gets garbled.
	const directory = "" &redef;

	## The working directory for data cluster nodes created by this
	## agent. If you make this a relative path, note that the path is
	## relative to the agent's working directory, since it creates data
	## cluster nodes.
	const cluster_directory = "" &redef;

	## Returns a :zeek:see:`Management::Instance` describing this
	## instance (its agent name plus listening address/port, as applicable).
	global instance: function(): Management::Instance;

	## Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
	## Similar to :zeek:see:`Management::Agent::instance`, but with slightly different
	## data format.
	global endpoint_info: function(): Broker::EndpointInfo;
}

function instance(): Management::Instance
	{
	local epi = endpoint_info();
	return Management::Instance($name=epi$id,
	    $host=to_addr(epi$network$address),
	    $listen_port=epi$network$bound_port);
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;
	local network: Broker::NetworkInfo;

	if ( Management::Agent::name != "" )
		epi$id = Management::Agent::name;
	else
		epi$id = fmt("agent-%s", gethostname());

	if ( Management::Agent::listen_address != "" )
		network$address = Management::Agent::listen_address;
	else if ( Management::default_address != "" )
		network$address = Management::default_address;
	else
		network$address = "127.0.0.1";

	if ( Management::Agent::listen_port != "" )
		network$bound_port = to_port(Management::Agent::listen_port);
	else
		network$bound_port = Management::Agent::default_port;

	epi$network = network;

	return epi;
	}
