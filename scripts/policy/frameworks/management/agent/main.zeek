##! This is the main "runtime" of a cluster agent. Zeek does not load this
##! directly; rather, the agent's bootstrapping module (in ./boot.zeek)
##! specifies it as the script to run in the node newly created via Zeek's
##! supervisor.

@load base/frameworks/broker
@load base/utils/paths

@load policy/frameworks/management
@load policy/frameworks/management/node/api
@load policy/frameworks/management/node/config
@load policy/frameworks/management/supervisor/api
@load policy/frameworks/management/supervisor/config

@load ./api
@load ./config

module Management::Agent::Runtime;

# This export is mainly to appease Zeekygen's need to understand redefs of the
# Request record below. Without it, it fails to establish link targets for the
# tucked-on types.
export {
	## Request state specific to the agent's Supervisor interactions.
	type SupervisorState: record {
		## Name of the node the Supervisor is acting on, if applicable.
		node: string &default="";
		## The result of a status request.
		status: Supervisor::Status &optional;
		## The result of a restart request.
		restart_result: bool &optional;
	};

	## Request state for deploy requests.
	type DeployState: record {
		## Zeek cluster nodes the provided configuration requested
		## and which have not yet checked in with the agent.
		nodes_pending: set[string];
	};

	## Request state for node dispatches, tracking the requested action
	## as well as received responses.
	type NodeDispatchState: record {
		## The dispatched action. The first string is a command,
		## any remaining strings its arguments.
		action: vector of string;

		## Request state for every node managed by this agent.
		requests: set[string] &default=set();
	};

	## Request state for restart requests, tracking received responses.
	type RestartState: record {
		## Request state for every node the agent asks the Supervisor
		## to restart.
		requests: set[string] &default=set();
	};

	# When Management::Agent::archive_logs is T (the default) and the
	# logging configuration doesn't permanently prevent archival
	# (e.g. because log rotation isn't configured), the agent triggers this
	# event each Management::Controller::archive_interval to initiate log
	# archival.
	#
	# run_archival: whether to actually invoke the archiver or just
	#     ensure (re-)scheduling.
	#
	global trigger_log_archival: event(run_archival: bool &default=T);
}

# We need to go out of our way here to avoid colliding record field names with
# the similar redef in the controller -- not because of real-world use, but
# because Zeekygen loads it both during documentation extraction. Suffix all
# members with _agent to disambiguate.
redef record Management::Request::Request += {
	supervisor_state_agent: SupervisorState &optional;
	deploy_state_agent: DeployState &optional;
	node_dispatch_state_agent: NodeDispatchState &optional;
	restart_state_agent: RestartState &optional;
};

# Tag our logs correctly
redef Management::role = Management::AGENT;

# Conduct more frequent table expiration checks. This helps get more predictable
# timing for request timeouts and only affects the agent, which is mostly idle.
redef table_expire_interval = 2 sec;

# Tweak the request timeout so it's relatively quick, and quick enough always to
# time out strictly before the controller's request state (at 10 sec).
redef Management::Request::timeout_interval = 5 sec;

# Returns the effective agent topic for this agent.
global agent_topic: function(): string;

# Returns the effective supervisor's address and port, to peer with
global supervisor_network_info: function(): Broker::NetworkInfo;

# Wrapper for sending a SupervisorControl::status_request to the Supervisor.
# Establishes a request object for the transaction, and returns it.
global supervisor_status: function(node: string): Management::Request::Request;

# Wrapper for sending a SupervisorControl::create_request to the Supervisor.
# Establishes a request object for the transaction, and returns it.
global supervisor_create: function(nc: Supervisor::NodeConfig): Management::Request::Request;

# Wrapper for sending a SupervisorControl::destroy_request to the Supervisor.
# Establishes a request object for the transaction, and returns it.
global supervisor_destroy: function(node: string): Management::Request::Request;

# Wrapper for sending a SupervisorControl::restart_request to the Supervisor.
# Establishes a request object for the transaction, and returns it.
global supervisor_restart: function(node: string): Management::Request::Request;

# Finalizes a deploy_request transaction: cleans up remaining state
# and sends response event.
global send_deploy_response: function(req: Management::Request::Request);

# Callback completing a deploy_request after the Supervisor has delivered
# a status response.
global deploy_request_finish: function(req: Management::Request::Request);

# Callback completing a restart_request after the Supervisor has delivered
# a restart response.
global restart_request_finish: function(req: Management::Request::Request);

# Callback completing a get_nodes_request after the Supervisor has delivered
# a status response.
global get_nodes_request_finish: function(req: Management::Request::Request);

# Whether we have peered with the Supervisor. We need to make sure we've peered
# prior to controller interactions, since we might otherwise send requests to
# the Supervisor that it never received.
global g_supervisor_peered = F;

# The global configuration, as deployed by the controller.
global g_config: Management::Configuration;

# A map to make other instance info accessible
global g_instances: table[string] of Management::Instance;

# A map for the nodes we run on this instance, via this agent.
global g_nodes: table[string] of Management::Node;

# The request ID of the most recent config deployment from the controller.  We
# track it until the nodes_pending set in the corresponding request's
# DeployState is cleared out, or the corresponding request state hits a timeout.
global g_config_reqid_pending: string = "";

# The complete node map employed by the supervisor to describe the cluster
# topology to newly forked nodes. We refresh it when we receive new
# configurations.
global g_cluster: table[string] of Supervisor::ClusterEndpoint;

# The most recent output contexts we've received from the Supervisor, for
# any of our nodes.
global g_outputs: table[string] of Management::NodeOutputs;


function agent_topic(): string
	{
	local epi = Management::Agent::endpoint_info();
	return Management::Agent::topic_prefix + "/" + epi$id;
	}

function supervisor_network_info(): Broker::NetworkInfo
	{
	# The Supervisor's address defaults to Broker's default, which
	# relies on ZEEK_DEFAULT_LISTEN_ADDR and so might just be "". Broker
	# internally falls back to listening on any; we pick 127.0.0.1.
	local address = Broker::default_listen_address;

	if ( address == "" )
		address = "127.0.0.1";

	return Broker::NetworkInfo($address=address, $bound_port=Broker::default_port);
	}

function send_deploy_response(req: Management::Request::Request)
	{
	local node: string;
	local res: Management::Result;

	# Put together the results vector for the response event.
	for ( node in g_nodes )
		{
		res = Management::Result(
		    $reqid = req$id,
		    $instance = Management::Agent::get_name(),
		    $node = node);

		if ( node in req$deploy_state_agent$nodes_pending )
			{
			# This node failed.
			res$success = F;

			# Pull in any stdout/stderr context we might have.
			if ( node in g_outputs )
				res$data = g_outputs[node];
			}

		# Add this result to the overall response
		req$results[|req$results|] = res;
		}

	Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
	    Management::result_vec_to_string(req$results)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::deploy_response, req$id, req$results);

	Management::Request::finish(req$id);

	if ( req$id == g_config_reqid_pending )
		g_config_reqid_pending = "";
	}

event Management::Agent::Runtime::trigger_log_archival(run_archival: bool)
	{
	# This is currently final, but could be considered dynamically in the
	# future if we make this an option.
	if ( Management::Agent::archive_logs == F )
		return;

	local ival = Management::Agent::archive_interval;

	# Fall back to the default rotation interval when not set explicitly:
	if ( ival == 0 secs )
		ival = Log::default_rotation_interval;

	# Without a default rotation interval individual log streams might still
	# have rotation enabled, and we could scan all filters to determine
	# their rotation configuration. But it's not clear that this is
	# intuitive or needed, since it's uncommon to want rotation for only
	# some logs. So we simply don't proceed if it's not configured.
	if ( ival == 0 secs )
		return;

	local cmd = Management::Agent::archive_cmd;

	if ( cmd == "" )
		{
		cmd = join_string_vec(vector(Installation::root_dir, "bin"), "/");
		cmd = build_path_compressed(cmd, "zeek-archiver");
		}

	# The logging framework creates the rotation directory on demand, so
	# only trigger archival when it exists. Don't warn when it does not:
	# this will often be expected, since in larger clusters many instances
	# may not run loggers.
	if ( run_archival && file_size(Log::default_rotation_dir) > 0 )
		{
		cmd = fmt("%s -1 %s %s",
		    cmd, Log::default_rotation_dir,
		    Management::Agent::archive_dir);

		Management::Log::info(fmt("triggering log archival via '%s'", cmd));
		system(cmd);
		}

	schedule ival { Management::Agent::Runtime::trigger_log_archival() };
	}

event Management::Supervisor::API::notify_node_exit(node: string, outputs: Management::NodeOutputs)
	{
	Management::Log::info(fmt("rx Management::Supervisor::API::notify_node_exit %s", node));

	if ( node in g_nodes )
		g_outputs[node] = outputs;
	}

event SupervisorControl::status_response(reqid: string, result: Supervisor::Status)
	{
	Management::Log::info(fmt("rx SupervisorControl::status_response %s", reqid));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	req$supervisor_state_agent$status = result;

	Management::Request::finish(reqid);
	}

event SupervisorControl::create_response(reqid: string, result: string)
	{
	Management::Log::info(fmt("rx SupervisorControl::create_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;

	if ( |result| > 0 )
		{
		local msg = fmt("failed to create node %s: %s", name, result);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

event SupervisorControl::destroy_response(reqid: string, result: bool)
	{
	Management::Log::info(fmt("rx SupervisorControl::destroy_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;

	if ( ! result )
		{
		local msg = fmt("failed to destroy node %s, %s", name, reqid);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

event SupervisorControl::restart_response(reqid: string, result: bool)
	{
	Management::Log::info(fmt("rx SupervisorControl::restart_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;
	req$supervisor_state_agent$restart_result = result;

	if ( ! result )
		{
		local msg = fmt("failed to restart node %s", name);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

function supervisor_status(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::status_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::status_request, req$id, node);

	return req;
	}

function supervisor_create(nc: Supervisor::NodeConfig): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = nc$name);

	Management::Log::info(fmt("tx SupervisorControl::create_request %s %s",
	    req$id, nc$name));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::create_request, req$id, nc);

	return req;
	}

function supervisor_destroy(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::destroy_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::destroy_request, req$id, node);

	return req;
	}

function supervisor_restart(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::restart_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::restart_request, req$id, node);

	return req;
	}

event Management::Agent::API::deploy_request(reqid: string, config: Management::Configuration, force: bool)
	{
	Management::Log::info(fmt("rx Management::Agent::API::deploy_request %s %s", reqid, config$id));

	local nodename: string;
	local node: Management::Node;
	local nc: Supervisor::NodeConfig;
	local res: Management::Result;

	# Special case: we're already running this configuration.
	if ( g_config$id == config$id && ! force )
		{
		res = Management::Result(
		    $reqid = reqid,
		    $instance = Management::Agent::get_name());

		Management::Log::info(fmt("already running config %s", config$id));
		Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
		    Management::result_to_string(res)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::deploy_response, reqid, vector(res));
		return;
		}

	local req = Management::Request::create(reqid);
	req$deploy_state_agent = DeployState();

	# Adopt the global configuration provided. The act of trying to launch
	# the requested nodes perturbs any existing ones one way or another, so
	# even if the launch fails it effectively is our new configuration.
	g_config = config;

	# Refresh the instances table:
	g_instances = table();
	for ( inst in config$instances )
		g_instances[inst$name] = inst;

	local sreq = supervisor_status("");
	sreq$parent_id = reqid;
	sreq$finish = deploy_request_finish;
	}

function deploy_request_finish(areq: Management::Request::Request)
	{
	local status = areq$supervisor_state_agent$status;

	for ( nodename in status$nodes )
		{
		if ( "ZEEK_MANAGEMENT_NODE" in status$nodes[nodename]$node$env )
			next;
		supervisor_destroy(status$nodes[nodename]$node$name);
		}

	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local res: Management::Result;
	local nc: Supervisor::NodeConfig;
	local node: Management::Node;

	# Refresh the cluster and nodes tables
	g_nodes = table();
	g_cluster = table();

	# Special case: the config contains no nodes. We can respond right away.
	if ( |g_config$nodes| == 0 )
		{
		g_config_reqid_pending = "";

		res = Management::Result(
		    $reqid = req$id,
		    $instance = Management::Agent::get_name());

		Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
		    Management::result_to_string(res)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::deploy_response, req$id, vector(res));
		return;
		}

	# Establish this request as the pending one:
	g_config_reqid_pending = req$id;

	for ( node in g_config$nodes )
		{
		# Filter the node set down to the ones this agent manages.
		if ( node$instance == Management::Agent::get_name() )
			{
			g_nodes[node$name] = node;
			add req$deploy_state_agent$nodes_pending[node$name];
			}

		# The cluster and supervisor frameworks require a port for every
		# node, using 0/unknown to signify "don't listen". The management
		# framework uses optional values, so here we map absent values
		# to 0/unknown.
		local p = 0/unknown;

		if ( node?$p )
			p = node$p;

		# Register the node in the g_cluster table. We use it below to
		# ship the cluster topology with node configs launched via the
		# Supervisor.
		local cep = Supervisor::ClusterEndpoint(
		    $role = node$role,
		    $host = g_instances[node$instance]$host,
		    $p = p);

		if ( node?$interface )
			cep$interface = node$interface;

		g_cluster[node$name] = cep;
		}

	# Apply the new configuration via the supervisor.
	#
	# XXX this should launch in the nodes in controlled order (loggers ->
	# manager -> proxies -> workers), ideally checking that one stage is up
	# before launching the next. This is tricky because that's not the point
	# of the Supervisor's response event. Until we have this, bootstrap
	# might be noisy, particular in the Broker log.

	for ( nodename in g_nodes )
		{
		node = g_nodes[nodename];
		node$state = Management::PENDING;

		nc = Supervisor::NodeConfig($name=nodename);

		local statedir = build_path(Management::get_state_dir(), "nodes");

		if ( ! mkdir(statedir) )
			Management::Log::warning(fmt("could not create state dir '%s'", statedir));

		statedir = build_path(statedir, nodename);

		if ( ! mkdir(statedir) )
			Management::Log::warning(fmt("could not create node state dir '%s'", statedir));

		nc$directory = statedir;

		if ( node?$interface )
			nc$interface = node$interface;
		if ( node?$cpu_affinity )
			nc$cpu_affinity = node$cpu_affinity;
		if ( node?$scripts )
			nc$addl_user_scripts = node$scripts;
		if ( node?$env )
			nc$env = node$env;

		# Always add the policy/management/node scripts to any cluster
		# node, since we require it to be able to communicate with the
		# node.
		nc$addl_user_scripts += "policy/frameworks/management/node";

		# We don't set nc$stdout_file/stderr_file here because the
		# Management framework's Supervisor shim manages those output
		# files itself. See frameworks/management/supervisor/main.zeek
		# for details.

		# XXX could use options to enable per-node overrides for
		# directory, stdout, stderr, others?

		nc$cluster = g_cluster;
		supervisor_create(nc);
		}

	# At this point we await Management::Node::API::notify_node_hello events
	# from the new nodes, or a timeout, whichever happens first. These
	# update the pending nodes in the request state, and eventually trigger
	# the deploy_response event back to the controller.
	}

event Management::Agent::API::get_nodes_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::get_nodes_request %s", reqid));

	local req = Management::Request::create(reqid);

	local sreq = supervisor_status("");
	sreq$parent_id = reqid;
	sreq$finish = get_nodes_request_finish;
	}

function get_nodes_request_finish(areq: Management::Request::Request)
	{
	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local res = Management::Result($reqid=req$id,
	    $instance=Management::Agent::get_name());

	local node_statuses: Management::NodeStatusVec;

	for ( node in areq$supervisor_state_agent$status$nodes )
		{
		local sns = areq$supervisor_state_agent$status$nodes[node]; # Supervisor node status
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

			# For cluster nodes, copy run state from g_nodes, our
			# live node status table.
			if ( node in g_nodes )
				cns$state = g_nodes[node]$state;

			# The supervisor's responses use 0/tcp (not 0/unknown)
			# when indicating an unused port because its internal
			# serialization always assumes TCP.
			if ( sns$node$cluster[node]$p != 0/tcp )
				cns$p = sns$node$cluster[node]$p;
			}
		else
			{
			if ( "ZEEK_MANAGEMENT_NODE" in sns$node$env )
				{
				local role = sns$node$env["ZEEK_MANAGEMENT_NODE"];
				if ( role == "CONTROLLER" )
					{
					cns$mgmt_role = Management::CONTROLLER;

					# Automatically declare the controller in running state
					# here -- we'd not have received a request that brought
					# us here otherwise.
					cns$state = Management::RUNNING;

					# The controller always listens, so the Zeek client can connect.
					cns$p = Management::Agent::endpoint_info()$network$bound_port;
					}
				else if ( role == "AGENT" )
					{
					cns$mgmt_role = Management::AGENT;

					# Similarly to above, always declare agent running. We are. :)
					cns$state = Management::RUNNING;

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

		# A PID is available if a supervised node has fully launched.
		if ( sns?$pid )
			cns$pid = sns$pid;

		node_statuses += cns;
		}

	res$data = node_statuses;

	Management::Log::info(fmt("tx Management::Agent::API::get_nodes_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::get_nodes_response, req$id, res);
	Management::Request::finish(req$id);
	}

event Management::Node::API::node_dispatch_response(reqid: string, result: Management::Result)
	{
	local node = "unknown node";
	if ( result?$node )
		node = result$node;

	Management::Log::info(fmt("rx Management::Node::API::node_dispatch_response %s from %s", reqid, node));

	# Retrieve state for the request we just got a response to
	local nreq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(nreq) )
		return;

	# Find the original request from the controller
	local req = Management::Request::lookup(nreq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	# Mark the responding node as done. Nodes normally fill their own name
	# into the result; we only double-check for resilience. Nodes failing to
	# report themselves would eventually lead to request timeout.
	if ( result?$node )
		{
		if ( result$node in req$node_dispatch_state_agent$requests )
			delete req$node_dispatch_state_agent$requests[result$node];
		else
			{
			# An unknown or duplicate response -- do nothing.
			Management::Log::debug(fmt("response %s not expected, ignoring", reqid));
			return;
			}
		}

	# The usual special treatment for Broker values that are of type "any":
	# confirm their type here based on the requested dispatch command.
	switch req$node_dispatch_state_agent$action[0]
		{
		case "get_id_value":
			if ( result?$data )
				result$data = result$data as string;
			break;
		default:
			Management::Log::error(fmt("unexpected dispatch command %s",
			    req$node_dispatch_state_agent$action[0]));
			break;
		}

	# The result has the reporting node filled in but not the agent/instance
	# (which the node doesn't know about), so add it now.
	result$instance = Management::Agent::instance()$name;

	# Add this result to the overall response
	req$results[|req$results|] = result;

	# If we still have pending queries out to the agents, do nothing: we'll
	# handle this soon, or our request will time out and we respond with
	# error.
	if ( |req$node_dispatch_state_agent$requests| > 0 )
		return;

	# Release the agent-nodes request state, since we now have all responses.
	Management::Request::finish(nreq$id);

	# Send response event back to controller and clean up main request state.
	Management::Log::info(fmt("tx Management::Agent::API::node_dispatch_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::node_dispatch_response, req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Agent::API::node_dispatch_request(reqid: string, action: vector of string, nodes: set[string])
	{
	Management::Log::info(fmt("rx Management::Agent::API::node_dispatch_request %s %s %s",
	    reqid, action, Management::Util::set_to_vector(nodes)));

	local node: string;
	local cluster_nodes: set[string];
	local nodes_final: set[string];

	for ( node in g_nodes )
		add cluster_nodes[node];

	# If this request includes cluster nodes to query, check if this agent
	# manages any of those nodes. If it doesn't, respond with an empty
	# results vector immediately. Note that any globally unknown nodes
	# that the client might have requested already got filtered by the
	# controller, so we don't need to worry about them here.

	if ( |nodes| > 0 )
		{
		nodes_final = nodes & cluster_nodes;

		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Agent::API::node_dispatch_response %s, no node overlap",
			    reqid));
			Broker::publish(agent_topic(),
			    Management::Agent::API::node_dispatch_response, reqid, vector());
			return;
			}
		}
	else if ( |g_nodes| == 0 )
		{
		# Special case: the client did not request specific nodes.  If
		# we aren't running any nodes, respond right away, since there's
		# nothing to dispatch to.
		Management::Log::info(fmt(
		    "tx Management::Agent::API::node_dispatch_response %s, no nodes registered",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::node_dispatch_response, reqid, vector());
		return;
		}
	else
		{
		# We send to all known nodes.
		nodes_final = cluster_nodes;
		}

	local res: Management::Result;
	local req = Management::Request::create(reqid);

	req$node_dispatch_state_agent = NodeDispatchState($action=action);

	# Build up dispatch state for tracking responses. We only dispatch to
	# nodes that are in state RUNNING, as those have confirmed they're ready
	# to communicate. For others, establish error state in now.
	for ( node in nodes_final )
		{
		if ( g_nodes[node]$state == Management::RUNNING )
			add req$node_dispatch_state_agent$requests[node];
		else
			{
			res = Management::Result($reqid=reqid,
			    $instance = Management::Agent::get_name(),
			    $success = F,
			    $error = fmt("cluster node %s not in running state", node),
			    $node=node);
			req$results += res;
			}
		}

	# Corner case: nothing is in state RUNNING.
	if ( |req$node_dispatch_state_agent$requests| == 0 )
		{
		Management::Log::info(fmt(
		    "tx Management::Agent::API::node_dispatch_response %s, no nodes running",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::node_dispatch_response, reqid, req$results);
		Management::Request::finish(req$id);
		return;
		}

	# We use a single request record to track all node responses, and a
	# single event that Broker publishes to all nodes. We know when all
	# nodes have responded by checking the requests set we built up above.
	local nreq = Management::Request::create();
	nreq$parent_id = reqid;

	Management::Log::info(fmt("tx Management::Node::API::node_dispatch_request %s %s", nreq$id, action));
	Broker::publish(Management::Node::node_topic,
	    Management::Node::API::node_dispatch_request, nreq$id, action, nodes);
	}

event Management::Agent::API::agent_welcome_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_welcome_request %s", reqid));

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::get_name());

	Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::agent_welcome_response, reqid, res);
	}

event Management::Agent::API::agent_standby_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_standby_request %s", reqid));

	# We shut down any existing cluster nodes via an empty configuration,
	# and fall silent. We do not unpeer/disconnect (assuming we earlier
	# peered/connected -- otherwise there's nothing we can do here via
	# Broker anyway), mainly to keep open the possibility of running
	# cluster nodes again later.
	event Management::Agent::API::deploy_request("", Management::Configuration());

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::get_name());

	Management::Log::info(fmt("tx Management::Agent::API::agent_standby_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::agent_standby_response, reqid, res);
	}

function restart_request_finish(sreq: Management::Request::Request)
	{
	# This is the finish callback we set on requests to the Supervisor to
	# restart a node. We look up the parent request (the one sent to us by
	# the controller), mark the node in question as done, and respond to the
	# controller if we've handled all required nodes.

	local req = Management::Request::lookup(sreq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local node = sreq$supervisor_state_agent$node;

	local res = Management::Result(
	    $reqid = req$id,
	    $instance = Management::Agent::get_name(),
	    $node = node);

	if ( ! sreq$supervisor_state_agent$restart_result )
		{
		res$success = F;
		res$error = fmt("could not restart node %s", node);
		}

	req$results += res;

	if ( node in req$restart_state_agent$requests )
		{
		delete req$restart_state_agent$requests[node];
		if ( |req$restart_state_agent$requests| > 0 )
			return;
		}

	Management::Log::info(fmt(
	    "tx Management::Agent::API::restart_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::restart_response,
	    req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Agent::API::restart_request(reqid: string,  nodes: set[string])
	{
	# This is very similar to node_dispatch_request, because it too works
	# with a list of nodes that needs to be dispatched to agents.

	Management::Log::info(fmt("rx Management::Agent::API::restart_request %s %s",
	    reqid, Management::Util::set_to_vector(nodes)));

	local node: string;
	local cluster_nodes: set[string];
	local nodes_final: set[string];

	for ( node in g_nodes )
		add cluster_nodes[node];

	# If this request includes cluster nodes to query, check if this agent
	# manages any of those nodes. If it doesn't, respond with an empty
	# results vector immediately. Note that any globally unknown nodes
	# that the client might have requested already got filtered by the
	# controller, so we don't need to worry about them here.

	if ( |nodes| > 0 )
		{
		nodes_final = nodes & cluster_nodes;

		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Agent::API::restart_response %s, no node overlap",
			    reqid));
			Broker::publish(agent_topic(),
			    Management::Agent::API::restart_response, reqid, vector());
			return;
			}
		}
	else if ( |g_nodes| == 0 )
		{
		# Special case: the client did not request specific nodes.  If
		# we aren't running any nodes, respond right away, since there's
		# nothing to restart.
		Management::Log::info(fmt(
		    "tx Management::Agent::API::restart_response %s, no nodes registered",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::restart_response, reqid, vector());
		return;
		}
	else
		{
		# We restart all nodes.
		nodes_final = cluster_nodes;
		}

	local res: Management::Result;
	local req = Management::Request::create(reqid);

	req$restart_state_agent = RestartState();

	# Build up state for tracking responses.
	for ( node in nodes_final )
		add req$restart_state_agent$requests[node];

	# Ask the Supervisor to restart nodes. We need to enumerate the nodes
	# because restarting all (via "") would hit the agent (and the
	# controller, if co-located).
	for ( node in nodes_final )
		{
		local sreq = supervisor_restart(node);
		sreq$parent_id = reqid;
		sreq$finish = restart_request_finish;

		if ( node in g_nodes )
			g_nodes[node]$state = Management::PENDING;
		}
	}

event Management::Node::API::notify_node_hello(node: string)
	{
	Management::Log::info(fmt("rx Management::Node::API::notify_node_hello %s", node));

	# This node is now running; update its state:
	if ( node in g_nodes )
		g_nodes[node]$state = Management::RUNNING;

	# Look up the deploy request this node launch was part of (if
	# any), and check it off. If it was the last node we expected to launch,
	# finalize the request and respond to the controller.

	local req = Management::Request::lookup(g_config_reqid_pending);

	if ( Management::Request::is_null(req) || ! req?$deploy_state_agent )
		return;

	if ( node in req$deploy_state_agent$nodes_pending )
		{
		delete req$deploy_state_agent$nodes_pending[node];
		if ( |req$deploy_state_agent$nodes_pending| == 0 )
			send_deploy_response(req);
		}
	}

event Management::Request::request_expired(req: Management::Request::Request)
	{
	Management::Log::info(fmt("request %s timed out", req$id));

	local res = Management::Result($reqid=req$id,
	    $instance = Management::Agent::get_name(),
	    $success = F,
	    $error = "request timed out");

	req$results += res;

	if ( req?$deploy_state_agent )
		{
		send_deploy_response(req);
		# This timeout means we no longer have a pending request.
		g_config_reqid_pending = "";
		}

	if ( req?$restart_state_agent )
		{
		Management::Log::info(fmt("tx Management::Agent::API::restart_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::restart_response, req$id, req$results);
		}
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	Management::Log::debug(fmt("broker peer %s added: %s", peer, msg));

	local sni = supervisor_network_info();

	if ( peer$network$address == sni$address && peer$network$bound_port == sni$bound_port )
		g_supervisor_peered = T;

	# If the Supervisor hasn't yet peered with us, don't broadcast
	# notify_agent_hello. Doing so would exposes a race: we might receive
	# commands from the controller that lead to requests to the Supervisor
	# that it won't yet receive. It's easier to handle this here than to
	# push the wait into all types of received commands.
	if ( g_supervisor_peered == F )
		return;

	# Supervisor aside, this does not (cannot?) immediately verify that the
	# new peer is in fact a controller, so we might send this in vain.
	# Controllers register the agent upon receipt of the event.
	local epi = Management::Agent::endpoint_info();

	Broker::publish(agent_topic(),
	    Management::Agent::API::notify_agent_hello,
	    epi$id, Broker::node_id(),
	    Management::Agent::controller$address != "0.0.0.0",
	    Management::Agent::API::version);
	}

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();

	# The agent needs to peer with the supervisor -- this doesn't currently
	# happen automatically.
	local sni = supervisor_network_info();
	Broker::peer(sni$address, sni$bound_port, Broker::default_listen_retry);

	# Agents need receive communication targeted at it, any responses
	# from the supervisor, and any responses from cluster nodes.
	Broker::subscribe(agent_topic());
	Broker::subscribe(SupervisorControl::topic_prefix);
	Broker::subscribe(Management::Node::node_topic);
	Broker::subscribe(Management::Supervisor::topic_prefix);

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

	if ( Management::Agent::archive_logs )
		schedule 0 secs { Management::Agent::Runtime::trigger_log_archival(F) };

	Management::Log::info(fmt("agent is live, Broker ID %s", Broker::node_id()));
	}
