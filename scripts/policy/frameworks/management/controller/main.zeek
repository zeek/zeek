##! This is the main "runtime" of the Management framework's controller. Zeek
##! does not load this directly; rather, the controller's bootstrapping module
##! (in ./boot.zeek) specifies it as the script to run in the node newly created
##! by the supervisor.

@load base/frameworks/broker

@load policy/frameworks/management
@load policy/frameworks/management/agent/config # For the agent topic prefix
@load policy/frameworks/management/agent/api

@load ./api
@load ./config

module Management::Controller::Runtime;

# This export is mainly to appease Zeekygen's need to understand redefs of the
# Request record below. Without it, it fails to establish link targets for the
# tucked-on types.
export {
	## Request state specific to
	## :zeek:see:`Management::Controller::API::set_configuration_request` and
	## :zeek:see:`Management::Controller::API::set_configuration_response`.
	type SetConfigurationState: record {
		## The cluster configuration established with this request
		config: Management::Configuration;
		## Request state for every controller/agent transaction.
		requests: set[string] &default=set();
	};

	## Request state specific to
	## :zeek:see:`Management::Controller::API::get_nodes_request` and
	## :zeek:see:`Management::Controller::API::get_nodes_response`.
	type GetNodesState: record {
		## Request state for every controller/agent transaction.
		requests: set[string] &default=set();
	};

	## Dummy state for internal state-keeping test cases.
	type TestState: record { };
}

redef record Management::Request::Request += {
	set_configuration_state: SetConfigurationState &optional;
	get_nodes_state: GetNodesState &optional;
	test_state: TestState &optional;
};

# Tag our logs correctly
redef Management::Log::role = Management::CONTROLLER;

global check_instances_ready: function();
global add_instance: function(inst: Management::Instance);
global drop_instance: function(inst: Management::Instance);

global null_config: function(): Management::Configuration;
global is_null_config: function(config: Management::Configuration): bool;

# Checks whether the given instance is one that we know with different
# communication settings: a a different peering direction, a different listening
# port, etc. Used as a predicate to indicate when we need to drop the existing
# one from our internal state.
global is_instance_connectivity_change: function
    (inst: Management::Instance): bool;

# The set of agents the controller interacts with to manage to currently
# configured cluster. This may be a subset of all the agents known to the
# controller, as tracked by the g_instances_known set. They key is the instance
# name and should match the $name member of the corresponding instance record.
global g_instances: table[string] of Management::Instance = table();

# The set of instances that have checked in with the controller. This is a
# superset of g_instances, since it covers any agent that has sent us a
# notify_agent_hello event.
global g_instances_known: set[string] = set();

# A corresponding set of instances/agents that we track in order to understand
# when all of the above instances have sent agent_welcome_response events. (An
# alternative would be to use a record that adds a single state bit for each
# instance, and store that above.)
global g_instances_ready: set[string] = set();

# The request ID of the most recent configuration update that's come in from
# a client. We track it here until we know we are ready to communicate with all
# agents required by the update.
global g_config_reqid_pending: string = "";

# The most recent configuration we have successfully deployed. This is also
# the one we send whenever the client requests it.
global g_config_current: Management::Configuration;

function send_config_to_agents(req: Management::Request::Request,
                               config: Management::Configuration)
	{
	for ( name in g_instances )
		{
		if ( name !in g_instances_ready )
			next;

		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();
		areq$parent_id = req$id;

		# We track the requests sent off to each agent. As the
		# responses come in, we delete them. Once the requests
		# set is empty, we respond back to the client.
		add req$set_configuration_state$requests[areq$id];

		# We could also broadcast just once on the agent prefix, but
		# explicit request/response pairs for each agent seems cleaner.
		Management::Log::info(fmt("tx Management::Agent::API::set_configuration_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, Management::Agent::API::set_configuration_request, areq$id, config);
		}
	}

# This is the &on_change handler for the g_instances_ready set, meaning
# it runs whenever a required agent has confirmed it's ready.
function check_instances_ready()
	{
	local cur_instances: set[string];

	for ( inst in g_instances )
		add cur_instances[inst];

	if ( cur_instances == g_instances_ready )
		event Management::Controller::API::notify_agents_ready(cur_instances);
	}

function add_instance(inst: Management::Instance)
	{
	g_instances[inst$name] = inst;

	if ( inst?$listen_port )
		Broker::peer(cat(inst$host), inst$listen_port,
		             Management::connect_retry);

	if ( inst$name in g_instances_known )
		{
		# The agent has already peered with us. Send welcome to indicate
		# it's part of cluster management. Once it responds, we update
		# the set of ready instances and proceed as feasible with config
		# deployments.

		local req = Management::Request::create();

		Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_request to %s", inst$name));
		Broker::publish(Management::Agent::topic_prefix + "/" + inst$name,
		                Management::Agent::API::agent_welcome_request, req$id);
		}
	}

function drop_instance(inst: Management::Instance)
	{
	if ( inst$name !in g_instances )
		return;

	# Send the agent a standby so it shuts down its cluster nodes & state
	Management::Log::info(fmt("tx Management::Agent::API::agent_standby_request to %s", inst$name));
	Broker::publish(Management::Agent::topic_prefix + "/" + inst$name,
	                Management::Agent::API::agent_standby_request, "");

	delete g_instances[inst$name];

	if ( inst$name in g_instances_ready )
		delete g_instances_ready[inst$name];

	# The agent remains in g_instances_known, to track that we're able
	# to communicate with it in case it's required again.

	Management::Log::info(fmt("dropped instance %s", inst$name));
	}

function null_config(): Management::Configuration
	{
	return Management::Configuration($id="");
	}

function is_null_config(config: Management::Configuration): bool
	{
	return config$id == "";
	}

function is_instance_connectivity_change(inst: Management::Instance): bool
	{
	# If we're not tracking this instance as part of a cluster config, it's
	# not a change. (More precisely: we cannot say whether it's changed.)
	if ( inst$name !in g_instances )
		return F;

	# The agent has peered with us and now uses a different host.
	# XXX 0.0.0.0 is a workaround until we've resolved how agents that peer
	# with us obtain their identity. Broker ID?
	if ( inst$host != 0.0.0.0 && inst$host != g_instances[inst$name]$host )
		return T;

	# The agent has a listening port and the one we know does not, or vice
	# versa. I.e., this is a change in the intended peering direction.
	if ( inst?$listen_port != g_instances[inst$name]?$listen_port )
		return T;

	# Both have listening ports, but they differ.
	if ( inst?$listen_port && g_instances[inst$name]?$listen_port &&
	     inst$listen_port != g_instances[inst$name]$listen_port )
		return T;

	return F;
	}

event Management::Controller::API::notify_agents_ready(instances: set[string])
	{
	local insts = Management::Util::set_to_vector(instances);

	Management::Log::info(fmt("rx Management::Controller::API:notify_agents_ready %s",
	    join_string_vec(insts, ",")));

	local req = Management::Request::lookup(g_config_reqid_pending);

	# If there's no pending request, when it's no longer available, or it
	# doesn't have config state, don't do anything else.
	if ( Management::Request::is_null(req) || ! req?$set_configuration_state )
		return;

	# All instances requested in the pending configuration update are now
	# known to us. Send them the config. As they send their response events
	# we update the client's request state and eventually send the response
	# event to the it.
	send_config_to_agents(req, req$set_configuration_state$config);
	}

event Management::Agent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	Management::Log::info(fmt("rx Management::Agent::API::notify_agent_hello %s %s", instance, host));

	# When an agent checks in with a mismatching API version, we log the
	# fact and drop its state, if any.
	if ( api_version != Management::Controller::API::version )
		{
		Management::Log::warning(
		    fmt("instance %s/%s has checked in with incompatible API version %s",
		        instance, host, api_version));

		if ( instance in g_instances )
			drop_instance(g_instances[instance]);
		if ( instance in g_instances_known )
			delete g_instances_known[instance];

		return;
		}

	add g_instances_known[instance];

	if ( instance in g_instances && instance !in g_instances_ready )
		{
		# We need this instance for our cluster and have full context for
		# it from the configuration. Tell agent.
		local req = Management::Request::create();

		Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_request to %s", instance));
		Broker::publish(Management::Agent::topic_prefix + "/" + instance,
		                Management::Agent::API::agent_welcome_request, req$id);
		}
	}

event Management::Agent::API::agent_welcome_response(reqid: string, result: Management::Result)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_welcome_response %s", reqid));

	local req = Management::Request::lookup(reqid);

	if ( Management::Request::is_null(req) )
		return;

	Management::Request::finish(req$id);

	# An agent we've been waiting to hear back from is ready for cluster
	# work. Double-check we still want it, otherwise drop it.

	if ( ! result$success || result$instance !in g_instances )
		{
		Management::Log::info(fmt(
		    "tx Management::Agent::API::agent_standby_request to %s", result$instance));
		Broker::publish(Management::Agent::topic_prefix + "/" + result$instance,
		                Management::Agent::API::agent_standby_request, "");
		return;
		}

	add g_instances_ready[result$instance];
	Management::Log::info(fmt("instance %s ready", result$instance));

	check_instances_ready();
	}

event Management::Agent::API::notify_change(instance: string, n: Management::Node,
                                       old: Management::State,
                                       new: Management::State)
	{
	# XXX TODO
	}

event Management::Agent::API::notify_error(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event Management::Agent::API::notify_log(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event Management::Agent::API::set_configuration_response(reqid: string, result: Management::Result)
	{
	Management::Log::info(fmt("rx Management::Agent::API::set_configuration_response %s", reqid));

	# Retrieve state for the request we just got a response to
	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;

	# Release the request, which is now done.
	Management::Request::finish(areq$id);

	# Find the original request from the client
	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	# Add this result to the overall response
	req$results[|req$results|] = result;

	# Mark this request as done by removing it from the table of pending
	# ones. The following if-check should always be true.
	if ( areq$id in req$set_configuration_state$requests )
		delete req$set_configuration_state$requests[areq$id];

	# If there are any pending requests to the agents, we're
	# done: we respond once every agent has responed (or we time out).
	if ( |req$set_configuration_state$requests| > 0 )
		return;

	# All set_configuration requests to instances are done, so adopt the
	# client's requested configuration as the new one and respond back to
	# client.
	g_config_current = req$set_configuration_state$config;
	g_config_reqid_pending = "";

	Management::Log::info(fmt("tx Management::Controller::API::set_configuration_response %s",
	                          Management::Request::to_string(req)));
	event Management::Controller::API::set_configuration_response(req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Controller::API::set_configuration_request(reqid: string, config: Management::Configuration)
	{
	Management::Log::info(fmt("rx Management::Controller::API::set_configuration_request %s", reqid));

	local res: Management::Result;
	local req = Management::Request::create(reqid);

	req$set_configuration_state = SetConfigurationState($config = config);

	# At the moment there can only be one pending request.
	if ( g_config_reqid_pending != "" )
		{
		res = Management::Result($reqid=reqid);
		res$success = F;
		res$error = fmt("request %s still pending", g_config_reqid_pending);
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::set_configuration_response %s",
		                          Management::Request::to_string(req)));
		event Management::Controller::API::set_configuration_response(req$id, req$results);
		Management::Request::finish(req$id);
		return;
		}

	# XXX validate the configuration:
	# - Are node instances among defined instances?
	# - Are all names unique?
	# - Are any node options understood?
	# - Do node types with optional fields have required values?
	# ...

	# The incoming request is now the pending one. It gets cleared when all
	# agents have processed their config updates successfully, or their
	# responses time out.
	g_config_reqid_pending = req$id;

	# Compare the instance configuration to our current one. If it matches,
	# we can proceed to deploying the new cluster topology. If it does
	# not, we need to establish connectivity with agents we connect to, or
	# wait until all instances that connect to us have done so. Either triggers
	# a notify_agents_ready event, upon which we then deploy the topology.

	# The current & new set of instance names.
	local insts_current: set[string];
	local insts_new: set[string];

	# A set of current instances not contained in the new config.
	# Those will need to get dropped.
	local insts_to_drop: set[string];

	# The opposite: new instances not yet in our current set. Those we will need
	# to establish contact with (or they with us).
	local insts_to_add: set[string];

	# The overlap: instances in both the current and new set. For those we verify
	# that we're actually dealign with the same entities, and might need to re-
	# connect if not.
	local insts_to_keep: set[string];

	# Alternative representation of insts_to_add, directly providing the instances.
	local insts_to_peer: table[string] of Management::Instance;

	# Helpful locals.
	local inst_name: string;
	local inst: Management::Instance;

	for ( inst_name in g_instances )
		add insts_current[inst_name];
	for ( inst in config$instances )
		add insts_new[inst$name];

	# Populate TODO lists for instances we need to drop, check, or add.
	insts_to_drop = insts_current - insts_new;
	insts_to_add = insts_new - insts_current;
	insts_to_keep = insts_new & insts_current;

	for ( inst in config$instances )
		{
		if ( inst$name in insts_to_add )
			{
			insts_to_peer[inst$name] = inst;
			next;
			}

		# Focus on the keepers: check for change in identity/location.
		if ( inst$name !in insts_to_keep )
			next;

		if ( is_instance_connectivity_change(inst) )
			{
			# The endpoint looks different. We drop the current one
			# and need to re-establish connectivity with the new
			# one.
			add insts_to_drop[inst$name];
			add insts_to_add[inst$name];
			}
		}

	# Process our TODO lists. Handle drops first, then additions, in
	# case we need to re-establish connectivity with an agent.

	for ( inst_name in insts_to_drop )
		drop_instance(g_instances[inst_name]);
	for ( inst_name in insts_to_peer )
		add_instance(insts_to_peer[inst_name]);

	# Updates to out instance tables are complete, now check if we're already
	# able to send the config to the agents:
	check_instances_ready();
	}

event Management::Controller::API::get_instances_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Controller::API::set_instances_request %s", reqid));

	local res = Management::Result($reqid = reqid);
	local insts: vector of Management::Instance;

	for ( i in g_instances )
		insts += g_instances[i];

	res$data = insts;

	Management::Log::info(fmt("tx Management::Controller::API::get_instances_response %s", reqid));
	event Management::Controller::API::get_instances_response(reqid, res);
	}

event Management::Agent::API::get_nodes_response(reqid: string, result: Management::Result)
	{
	Management::Log::info(fmt("rx Management::Agent::API::get_nodes_response %s", reqid));

	# Retrieve state for the request we just got a response to
	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;

	# Release the request, which is now done.
	Management::Request::finish(areq$id);

	# Find the original request from the client
	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	# Zeek's ingestion of an any-typed val via Broker yields an opaque
	# Broker DataVal. When Zeek forwards this val via another event it stays
	# in this opaque form. To avoid forcing recipients to distinguish
	# whether the val is of the actual, intended (any-)type or a Broker
	# DataVal wrapper, we explicitly cast it back to our intended Zeek
	# type. This test case demonstrates: broker.remote_event_vector_any
	result$data = result$data as Management::NodeStatusVec;

	# Add this result to the overall response
	req$results[|req$results|] = result;

	# Mark this request as done by removing it from the table of pending
	# ones. The following if-check should always be true.
	if ( areq$id in req$get_nodes_state$requests )
		delete req$get_nodes_state$requests[areq$id];

	# If we still have pending queries out to the agents, do nothing: we'll
	# handle this soon, or our request will time out and we respond with
	# error.
	if ( |req$get_nodes_state$requests| > 0 )
		return;

	Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s",
	                          Management::Request::to_string(req)));
	event Management::Controller::API::get_nodes_response(req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Controller::API::get_nodes_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Controller::API::get_nodes_request %s", reqid));

	# Special case: if we have no instances, respond right away.
	if ( |g_instances| == 0 )
		{
		Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s", reqid));
		event Management::Controller::API::get_nodes_response(reqid, vector(
		    Management::Result($reqid=reqid, $success=F,
		        $error="no instances connected")));
		return;
		}

	local req = Management::Request::create(reqid);
	req$get_nodes_state = GetNodesState();

	for ( name in g_instances )
		{
		if ( name !in g_instances_ready )
			next;

		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();

		areq$parent_id = req$id;
		add req$get_nodes_state$requests[areq$id];

		Management::Log::info(fmt("tx Management::Agent::API::get_nodes_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, Management::Agent::API::get_nodes_request, areq$id);
		}
	}

event Management::Request::request_expired(req: Management::Request::Request)
	{
	# Various handlers for timed-out request state. We use the state members
	# to identify how to respond.  No need to clean up the request itself,
	# since we're getting here via the request module's expiration
	# mechanism that handles the cleanup.
	local res: Management::Result;

	if ( req?$set_configuration_state )
		{
		# This timeout means we no longer have a pending request.
		g_config_reqid_pending = "";

		res = Management::Result($reqid=req$id);
		res$success = F;
		res$error = "request timed out";
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::set_configuration_response %s",
		                          Management::Request::to_string(req)));
		event Management::Controller::API::set_configuration_response(req$id, req$results);
		}

	if ( req?$get_nodes_state )
		{
		res = Management::Result($reqid=req$id);
		res$success = F;
		res$error = "request timed out";
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s",
		                          Management::Request::to_string(req)));
		event Management::Controller::API::get_nodes_response(req$id, req$results);
		}

	if ( req?$test_state )
		{
		res = Management::Result($reqid=req$id);
		res$success = F;
		res$error = "request timed out";

		Management::Log::info(fmt("tx Management::Controller::API::test_timeout_response %s", req$id));
		event Management::Controller::API::test_timeout_response(req$id, res);
		}
	}

event Management::Controller::API::test_timeout_request(reqid: string, with_state: bool)
	{
	Management::Log::info(fmt("rx Management::Controller::API::test_timeout_request %s %s", reqid, with_state));

	if ( with_state )
		{
		# This state times out and triggers a timeout response in the
		# above request_expired event handler.
		local req = Management::Request::create(reqid);
		req$test_state = TestState();
		}
	}

event zeek_init()
	{
	# Initialize null config at startup. We will replace it once we have
	# persistence, and again whenever we complete a client's
	# set_configuration request.
	g_config_current = null_config();

	# The controller always listens -- it needs to be able to respond to the
	# Zeek client. This port is also used by the agents if they connect to
	# the client. The client doesn't automatically establish or accept
	# connectivity to agents: agents are defined and communicated with as
	# defined via configurations defined by the client.

	local cni = Management::Controller::network_info();

	Broker::listen(cat(cni$address), cni$bound_port);

	Broker::subscribe(Management::Agent::topic_prefix);
	Broker::subscribe(Management::Controller::topic);

	# Events sent to the client:
	local events: vector of any = [
	    Management::Controller::API::get_instances_response,
	    Management::Controller::API::set_configuration_response,
	    Management::Controller::API::get_nodes_response,
	    Management::Controller::API::test_timeout_response
	    ];

	for ( i in events )
		Broker::auto_publish(Management::Controller::topic, events[i]);

	Management::Log::info("controller is live");
	}
