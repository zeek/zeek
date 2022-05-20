##! Configuration settings for a cluster agent.

@load policy/frameworks/management

# We source the controller configuration to obtain its network coordinates, so
# we can default to connecting to it.
@load policy/frameworks/management/controller/config

module Management::Agent;

export {
	## The name this agent uses to represent the cluster instance it
	## manages. Defaults to the value of the ZEEK_AGENT_NAME environment
	## variable. When that is unset and you don't redef the value,
	## the implementation defaults to "agent-<hostname>".
	const name = getenv("ZEEK_AGENT_NAME") &redef;

	## Agent stdout log configuration. If the string is non-empty, Zeek will
	## produce a free-form log (i.e., not one governed by Zeek's logging
	## framework) in the agent's working directory. If left empty, no such
	## log results.
	##
	## Note that the agent also establishes a "proper" Zeek log via the
	## :zeek:see:`Management::Log` module.
	const stdout_file = "stdout" &redef;

	## Agent stderr log configuration. Like :zeek:see:`Management::Agent::stdout_file`,
	## but for the stderr stream.
	const stderr_file = "stderr" &redef;

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
	## suffixes this with "/<name>", based on :zeek:see:`Management::Agent::get_name`.
	const topic_prefix = "zeek/management/agent" &redef;

	## The network coordinates of the controller. By default, the agent
	## connects locally to the controller at its default port. Assigning
	## a :zeek:see:`Broker::NetworkInfo` record with IP address "0.0.0.0"
	## means the controller should instead connect to the agent. If you'd
	## like to use that mode, make sure to set
	## :zeek:see:`Management::Agent::listen_address` and
	## :zeek:see:`Management::Agent::listen_port` as needed.
	const controller = Broker::NetworkInfo($address="127.0.0.1",
	    $bound_port=Management::Controller::network_info()$bound_port) &redef;

	## An optional custom output directory for stdout/stderr. Agent and
	## controller currently only log locally, not via the Zeek cluster's
	## logger node. This means that if both write to the same log file,
	## output gets garbled.
	const directory = "" &redef;

	## The working directory for Zeek cluster nodes created by this
	## agent. If you make this a relative path, note that the path is
	## relative to the agent's working directory, since it creates data
	## cluster nodes.
	const cluster_directory = "" &redef;

	## Returns the effective name of this agent.
	global get_name: function(): string;

	## Returns a :zeek:see:`Management::Instance` describing this
	## instance (its agent name plus listening address/port, as applicable).
	global instance: function(): Management::Instance;

	## Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
	## Similar to :zeek:see:`Management::Agent::instance`, but with slightly different
	## data format.
	global endpoint_info: function(): Broker::EndpointInfo;
}

function get_name(): string
	{
	if ( name != "" )
		return name;

	return fmt("agent-%s", gethostname());
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

	epi$id = get_name();

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
