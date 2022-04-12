##! This is the main "runtime" of a cluster agent. Zeek does not load this
##! directly; rather, the agent's bootstrapping module (in ./boot.zeek)
##! specifies it as the script to run in the node newly created via Zeek's
##! supervisor.

@load base/frameworks/broker
@load policy/frameworks/management
@load policy/frameworks/management/node/api
@load policy/frameworks/management/node/config

@load ./api
@load ./config

module Mangement::Agent::Runtime;

# This export is mainly to appease Zeekygen's need to understand redefs of the
# Request record below. Without it, it fails to establish link targets for the
# tucked-on types.
export {
	## Request state specific to the agent's Supervisor interactions.
	type SupervisorState: record {
		node: string; ##< Name of the node the Supervisor is acting on.
	};
}

redef record Management::Request::Request += {
	supervisor_state: SupervisorState &optional;
};

# Tag our logs correctly
redef Management::Log::role = Management::AGENT;

# The global configuration as passed to us by the controller
global g_config: Management::Configuration;

# A map to make other instance info accessible
global g_instances: table[string] of Management::Instance;

# A map for the nodes we run on this instance, via this agent.
global g_nodes: table[string] of Management::Node;

# The node map employed by the supervisor to describe the cluster
# topology to newly forked nodes. We refresh it when we receive
# new configurations.
global g_cluster: table[string] of Supervisor::ClusterEndpoint;


event SupervisorControl::create_response(reqid: string, result: string)
	{
	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( |result| > 0 )
		{
		local msg = fmt("failed to create node %s: %s", name, result);
		Management::Log::error(msg);
		event Management::Agent::API::notify_error(Management::Agent::name, msg, name);
		}

	Management::Request::finish(reqid);
	}

event SupervisorControl::destroy_response(reqid: string, result: bool)
	{
	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( ! result )
		{
		local msg = fmt("failed to destroy node %s, %s", name, reqid);
		Management::Log::error(msg);
		event Management::Agent::API::notify_error(Management::Agent::name, msg, name);
		}

	Management::Request::finish(reqid);
	}

function supervisor_create(nc: Supervisor::NodeConfig)
	{
	local req = Management::Request::create();
	req$supervisor_state = SupervisorState($node = nc$name);
	event SupervisorControl::create_request(req$id, nc);
	Management::Log::info(fmt("issued supervisor create for %s, %s", nc$name, req$id));
	}

function supervisor_destroy(node: string)
	{
	local req = Management::Request::create();
	req$supervisor_state = SupervisorState($node = node);
	event SupervisorControl::destroy_request(req$id, node);
	Management::Log::info(fmt("issued supervisor destroy for %s, %s", node, req$id));
	}

event Management::Agent::API::set_configuration_request(reqid: string, config: Management::Configuration)
	{
	Management::Log::info(fmt("rx Management::Agent::API::set_configuration_request %s", reqid));

	local nodename: string;
	local node: Management::Node;
	local nc: Supervisor::NodeConfig;
	local msg: string;

	# Adopt the global configuration provided.
	# XXX this can later handle validation and persistence
	# XXX should do this transactionally, only set when all else worked
	g_config = config;

	# Refresh the instances table:
	g_instances = table();
	for ( inst in config$instances )
		g_instances[inst$name] = inst;

	# Terminate existing nodes
	for ( nodename in g_nodes )
		supervisor_destroy(nodename);

	g_nodes = table();

	# Refresh the cluster and nodes tables

	g_cluster = table();
	for ( node in config$nodes )
		{
		if ( node$instance == Management::Agent::name )
			g_nodes[node$name] = node;

		# The cluster and supervisor frameworks require a port for every
		# node, using 0/unknown to signify "don't listen". We use
		# optional values and map an absent value to 0/unknown.
		local p = 0/unknown;

		if ( node?$p )
			p = node$p;

		local cep = Supervisor::ClusterEndpoint(
		    $role = node$role,
		    $host = g_instances[node$instance]$host,
		    $p = p);

		if ( node?$interface )
			cep$interface = node$interface;

		g_cluster[node$name] = cep;
		}

	# Apply the new configuration via the supervisor

	for ( nodename in g_nodes )
		{
		node = g_nodes[nodename];
		nc = Supervisor::NodeConfig($name=nodename);

		if ( Management::Agent::cluster_directory != "" )
			nc$directory = Management::Agent::cluster_directory;

		if ( node?$interface )
			nc$interface = node$interface;
		if ( node?$cpu_affinity )
			nc$cpu_affinity = node$cpu_affinity;
		if ( node?$scripts )
			nc$scripts = node$scripts;
		if ( node?$env )
			nc$env = node$env;

		# Always add the policy/management/node scripts to any cluster
		# node, since we require it to be able to communicate with the
		# node.
		nc$scripts[|nc$scripts|] = "policy/frameworks/management/node";

		# XXX could use options to enable per-node overrides for
		# directory, stdout, stderr, others?

		nc$cluster = g_cluster;
		supervisor_create(nc);
		}

	# XXX this currently doesn not fail if any of above problems occurred,
	# mainly due to the tediousness of handling the supervisor's response
	# events asynchonously. The only indication of error will be
	# notification events to the controller.

	if ( reqid != "" )
		{
		local res = Management::Result(
		    $reqid = reqid,
		    $instance = Management::Agent::name);

		Management::Log::info(fmt("tx Management::Agent::API::set_configuration_response %s",
		                          Management::result_to_string(res)));
		event Management::Agent::API::set_configuration_response(reqid, res);
		}
	}

event SupervisorControl::status_response(reqid: string, result: Supervisor::Status)
	{
	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;

	Management::Request::finish(reqid);

	local res = Management::Result(
	    $reqid = req$parent_id, $instance = Management::Agent::name);

	local node_statuses: Management::NodeStatusVec;

	for ( node in result$nodes )
		{
		local sns = result$nodes[node]; # Supervisor node status
		local cns = Management::NodeStatus(
			    $node=node, $state=Management::PENDING);

		# Identify the role of the node. For cluster roles (worker,
		# manager, etc) we derive this from the cluster node table.  For
		# agent and controller, we identify via environment variables
		# that the controller framework establishes upon creation (see
		# the respective boot.zeek scripts).
		if ( node in sns$node$cluster )
			{
			cns$cluster_role = sns$node$cluster[node]$role;

			# The supervisor's responses use 0/tcp (not 0/unknown)
			# when indicating an unused port because its internal
			# serialization always assumes TCP.
			if ( sns$node$cluster[node]$p != 0/tcp )
				cns$p = sns$node$cluster[node]$p;
			}
		else
			{
			if ( "ZEEK_CLUSTER_MGMT_NODE" in sns$node$env )
				{
				local role = sns$node$env["ZEEK_CLUSTER_MGMT_NODE"];
				if ( role == "CONTROLLER" )
					{
					cns$mgmt_role = Management::CONTROLLER;
					# The controller always listens, so the Zeek client can connect.
					cns$p = Management::Agent::endpoint_info()$network$bound_port;
					}
				else if ( role == "AGENT" )
					{
					cns$mgmt_role = Management::AGENT;
					# If we have a controller address, the agent connects to it
					# and does not listen. See zeek_init() below for similar logic.
					if ( Management::Agent::controller$address == "0.0.0.0" )
						cns$p = Management::Agent::endpoint_info()$network$bound_port;
					}
				else
					Management::Log::warning(fmt(
					    "unexpected cluster management node type '%'", role));
				}
			}

		# A PID is available if a supervised node has fully launched
		# and is therefore running.
		if ( sns?$pid )
			{
			cns$pid = sns$pid;
			cns$state = Management::RUNNING;
			}

		node_statuses += cns;
		}

	res$data = node_statuses;

	Management::Log::info(fmt("tx Management::Agent::API::get_nodes_response %s",
	                          Management::result_to_string(res)));
	event Management::Agent::API::get_nodes_response(req$parent_id, res);
	}

event Management::Agent::API::get_nodes_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::get_nodes_request %s", reqid));

	local req = Management::Request::create();
	req$parent_id = reqid;

	event SupervisorControl::status_request(req$id, "");
	Management::Log::info(fmt("issued supervisor status, %s", req$id));
	}

event Management::Agent::API::agent_welcome_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_welcome_request %s", reqid));

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::name);

	Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_response %s",
	                          Management::result_to_string(res)));
	event Management::Agent::API::agent_welcome_response(reqid, res);
	}

event Management::Agent::API::agent_standby_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_standby_request %s", reqid));

	# We shut down any existing cluster nodes via an empty configuration,
	# and fall silent. We do not unpeer/disconnect (assuming we earlier
	# peered/connected -- otherwise there's nothing we can do here via
	# Broker anyway), mainly to keep open the possibility of running
	# cluster nodes again later.
	event Management::Agent::API::set_configuration_request("", Management::Configuration());

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::name);

	Management::Log::info(fmt("tx Management::Agent::API::agent_standby_response %s",
	                          Management::result_to_string(res)));
	event Management::Agent::API::agent_standby_response(reqid, res);
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	# This does not (cannot?) immediately verify that the new peer
	# is in fact a controller, so we might send this in vain.
	# Controllers register the agent upon receipt of the event.

	local epi = Management::Agent::endpoint_info();

	event Management::Agent::API::notify_agent_hello(epi$id,
	    to_addr(epi$network$address), Management::Agent::API::version);
	}

# XXX We may want a request timeout event handler here. It's arguably cleaner to
# send supervisor failure events back to the controller than to rely on its
# controller-agent request timeout to kick in.

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();
	local agent_topic = Management::Agent::topic_prefix + "/" + epi$id;

	# The agent needs to peer with the supervisor -- this doesn't currently
	# happen automatically. The address defaults to Broker's default, which
	# relies on ZEEK_DEFAULT_LISTEN_ADDR and so might just be "". Broker
	# internally falls back to listening on any; we pick 127.0.0.1.
	local supervisor_addr = Broker::default_listen_address;
	if ( supervisor_addr == "" )
		supervisor_addr = "127.0.0.1";

	Broker::peer(supervisor_addr, Broker::default_port, Broker::default_listen_retry);

	# Agents need receive communication targeted at it, any responses
	# from the supervisor, and any responses from cluster nodes.
	Broker::subscribe(agent_topic);
	Broker::subscribe(SupervisorControl::topic_prefix);
	Broker::subscribe(Management::Node::node_topic);

	# Auto-publish a bunch of events. Glob patterns or module-level
	# auto-publish would be helpful here.
	Broker::auto_publish(agent_topic, Management::Agent::API::get_nodes_response);
	Broker::auto_publish(agent_topic, Management::Agent::API::set_configuration_response);
	Broker::auto_publish(agent_topic, Management::Agent::API::agent_welcome_response);
	Broker::auto_publish(agent_topic, Management::Agent::API::agent_standby_response);

	Broker::auto_publish(agent_topic, Management::Agent::API::notify_agent_hello);
	Broker::auto_publish(agent_topic, Management::Agent::API::notify_change);
	Broker::auto_publish(agent_topic, Management::Agent::API::notify_error);
	Broker::auto_publish(agent_topic, Management::Agent::API::notify_log);

	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::create_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::status_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::destroy_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::restart_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::stop_request);

	# Establish connectivity with the controller.
	if ( Management::Agent::controller$address != "0.0.0.0" )
		{
		# We connect to the controller.
		Broker::peer(Management::Agent::controller$address,
		             Management::Agent::controller$bound_port,
		             Management::connect_retry);
		}

	# The agent always listens, to allow cluster nodes to peer with it.
	# If the controller connects to us, it also uses this port.
	Broker::listen(cat(epi$network$address), epi$network$bound_port);

	Management::Log::info("agent is live");
	}
