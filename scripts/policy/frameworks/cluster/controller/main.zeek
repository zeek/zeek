@load base/frameworks/broker

@load policy/frameworks/cluster/agent/config
@load policy/frameworks/cluster/agent/api

@load ./api
@load ./log
@load ./request
@load ./util

redef ClusterController::role = ClusterController::Types::CONTROLLER;

global check_instances_ready: function(insts: set[string], tc: TableChange, inst: string);
global add_instance: function(inst: ClusterController::Types::Instance);
global drop_instance: function(inst: ClusterController::Types::Instance);

global null_config: function(): ClusterController::Types::Configuration;
global is_null_config: function(config: ClusterController::Types::Configuration): bool;

# The desired set of agents the controller interact with, as provided by the
# most recent config update sent by the client. They key is a name of each
# instance. This should match the $name member of the instance records.
global g_instances: table[string] of ClusterController::Types::Instance = table();

# A corresponding set of instances/agents that we track in order to understand
# when all of the above instances have checked in with a notify_agent_hello
# event. (An alternative would be to use a record that adds a single state bit
# for each instance, and store that above.)
global g_instances_ready: set[string] = set() &on_change=check_instances_ready;

# The request ID of the most recent configuration update that's come in from
# a client. We track it here until we know we are ready to communicate with all
# agents required by the update.
global g_config_reqid_pending: string = "";

# The most recent configuration we have successfully deployed. This is also
# the one we send whenever the client requests it.
global g_config_current: ClusterController::Types::Configuration;

function send_config_to_agents(req: ClusterController::Request::Request,
                               config: ClusterController::Types::Configuration)
	{
	for ( name in g_instances )
		{
		local agent_topic = ClusterAgent::topic_prefix + "/" + name;
		local areq = ClusterController::Request::create();
		areq$parent_id = req$id;

		# We track the requests sent off to each agent. As the
		# responses come in, we can check them off as completed,
		# and once all are, we respond back to the client.
		req$set_configuration_state$requests += areq;

		# We could also broadcast just once on the agent prefix, but
		# explicit request/response pairs for each agent seems cleaner.
		ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, ClusterAgent::API::set_configuration_request, areq$id, config);
		}
	}

# This is the &on_change handler for the g_instances_ready set.
function check_instances_ready(insts: set[string], tc: TableChange, inst: string)
	{
	local cur_instances: set[string];

	# See if the new update to the readiness set makes it match the current
	# instances. If so, trigger the notify_agents_ready event.
	if ( tc == TABLE_ELEMENT_NEW || tc == TABLE_ELEMENT_REMOVED )
		{
		for ( inst in g_instances )
			add cur_instances[inst];

		if ( cur_instances == g_instances_ready )
			{
			event ClusterController::API::notify_agents_ready(cur_instances);
			}
		}
	}

function add_instance(inst: ClusterController::Types::Instance)
	{
	g_instances[inst$name] = inst;

	if ( inst?$listen_port )
		Broker::peer(cat(inst$host), inst$listen_port,
		             ClusterController::connect_retry);
	}

function drop_instance(inst: ClusterController::Types::Instance)
	{
	if ( inst$name !in g_instances )
		return;

	# Send this agent a config that will terminate any data cluster
	# nodes it might have. This is "fire and forget" -- there will
	# not be a response.
	Broker::publish(ClusterAgent::topic_prefix + "/" + inst$name,
	                ClusterAgent::API::set_configuration_request,
	                "", ClusterController::Types::Configuration());

	# If the instance has a port, we peered with it, so now unpeer.
	if ( inst?$listen_port )
		Broker::unpeer(cat(inst$host), inst$listen_port );

	delete g_instances[inst$name];

	if ( inst$name in g_instances_ready )
		delete g_instances_ready[inst$name];

	ClusterController::Log::info(fmt("dropped instance %s", inst$name));
	}

function null_config(): ClusterController::Types::Configuration
	{
	return ClusterController::Types::Configuration($id="");
	}

function is_null_config(config: ClusterController::Types::Configuration): bool
	{
	return config$id == "";
	}

event ClusterController::API::notify_agents_ready(instances: set[string])
	{
	local insts = ClusterController::Util::set_to_vector(instances);

	ClusterController::Log::info(fmt("rx ClusterController::API:notify_agents_ready %s", join_string_vec(insts, ",")));

	# When all agents are ready, send them the pending config update.
	local req = ClusterController::Request::lookup(g_config_reqid_pending);

	# If the request isn't available or doesn't have config state, we just
	# clear it out and stop.
	if ( ClusterController::Request::is_null(req) || ! req?$set_configuration_state )
		{
		g_config_reqid_pending = "";
		return;
		}

	# All instances requested in the pending configuration update are now
	# known to us. Send them the config. As they send their response events
	# we update the client's request state and eventually send the response
	# event to the it.
	send_config_to_agents(req, req$set_configuration_state$config);

	# The request object continues to exist and will be referenced by the
	# responses coming in, but there's no longer a pending config update to
	# track.
	g_config_reqid_pending = "";
	}

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	if ( instance !in g_instances )
		{
		# An unknown agent has checked in. This can happen with agentsthat aren't yet
		# showing in a configuration received by the client. We log at debug level only.
		ClusterController::Log::debug(
		    fmt("unknown instance %s/%s has checked in, ignoring", instance, host));
		return;
		}

	ClusterController::Log::info(fmt("rx ClusterAgent::API::notify_agent_hello %s %s", instance, host));

	local inst = g_instances[instance];

	# When a known agent checks in with a mismatching API version we kick it out.
	if ( api_version != ClusterController::API::version )
		{
		ClusterController::Log::warning(
		    fmt("instance %s/%s has checked in with incompatible API version %s, dropping",
		        instance, host, api_version));
		drop_instance(inst);
		return;
		}

	if ( instance !in g_instances_ready )
		{
		ClusterController::Log::info(fmt("instance %s/%s has checked in", instance, host));
		add g_instances_ready[instance];
		}

	Broker::publish(ClusterAgent::topic_prefix + "/" + instance,
	                ClusterAgent::API::notify_controller_hello, ClusterController::name,
	                to_addr(ClusterController::network_info()$address));
	}

event ClusterAgent::API::notify_change(instance: string, n: ClusterController::Types::Node,
                                       old: ClusterController::Types::State,
                                       new: ClusterController::Types::State)
	{
	# XXX TODO
	}

event ClusterAgent::API::notify_error(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event ClusterAgent::API::notify_log(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event ClusterAgent::API::set_configuration_response(reqid: string, result: ClusterController::Types::Result)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::set_configuration_response %s", reqid));

	# Retrieve state for the request we just got a response to
	local areq = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(areq) )
		return;

	# Record the result and mark the request as done. This also
	# marks the request as done in the parent-level request, since
	# these records are stored by reference.
	areq$results[0] = result; # We only have a single result here atm
	areq$finished = T;

	# Update the original request from the client:
	local req = ClusterController::Request::lookup(areq$parent_id);
	if ( ClusterController::Request::is_null(req) )
		return;

	# If there are any requests to the agents still unfinished,
	# we're not done yet.
	for ( i in req$set_configuration_state$requests )
		if ( ! req$set_configuration_state$requests[i]$finished )
			return;

	# All set_configuration requests to instances are done, so respond
	# back to client. We need to compose the result, aggregating
	# the results we got from the requests to the agents. In the
	# end we have one Result per instance requested in the
	# original set_configuration_request.
	#
	# XXX we can likely generalize result aggregation in the request module.
	for ( i in req$set_configuration_state$requests )
		{
		local r = req$set_configuration_state$requests[i];

		local success = T;
		local errors: string_vec;
		local instance = "";

		for ( j in r$results )
			{
			local res = r$results[j];
			instance = res$instance;

			if ( res$success )
				next;

			success = F;
			errors += fmt("node %s failed: %s", res$node, res$error);
			}

		req$results += ClusterController::Types::Result(
		    $reqid = req$id,
		    $instance = instance,
		    $success = success,
		    $error = join_string_vec(errors, ", ")
		);

		ClusterController::Request::finish(r$id);
		}

	# This is the point where we're really done with the original
	# set_configuration request. We adopt the configuration as the current
	# one.
	g_config_current = req$set_configuration_state$config;

	ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s",
	                                 ClusterController::Request::to_string(req)));
	event ClusterController::API::set_configuration_response(req$id, req$results);
	ClusterController::Request::finish(req$id);
	}

event ClusterController::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::set_configuration_request %s", reqid));

	local res: ClusterController::Types::Result;
	local req = ClusterController::Request::create(reqid);

	req$set_configuration_state = ClusterController::Request::SetConfigurationState($config = config);

	# At the moment there can only be one pending request.
	if ( g_config_reqid_pending != "" )
		{
		res = ClusterController::Types::Result($reqid=reqid);
		res$success = F;
		res$error = fmt("request %s still pending", g_config_reqid_pending);
		req$results += res;

		ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s",
		                                 ClusterController::Request::to_string(req)));
		event ClusterController::API::set_configuration_response(req$id, req$results);
		ClusterController::Request::finish(req$id);
		return;
		}

	# Compare the instance configuration to our current one. If it matches,
	# we can proceed to deploying the new data cluster topology. If it does
	# not, we need to establish connectivity with agents we connect to, or
	# wait until all instances that connect to us have done so. Either triggers
	# a notify_agents_ready event, upon which we then deploy the data cluster.

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
	local insts_to_peer: table[string] of ClusterController::Types::Instance;

	# Helpful locals.
	local inst_name: string;
	local inst: ClusterController::Types::Instance;

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

		# XXX 0.0.0.0 is a workaround until we've resolved
		# how agents that peer with us obtain their identity.
		# Broker ID?
		if ( ( inst$host != 0.0.0.0 && inst$host != g_instances[inst$name]$host ) ||
		     inst?$listen_port != g_instances[inst$name]?$listen_port ||
		     ( inst?$listen_port && g_instances[inst$name]?$listen_port &&
		       inst$listen_port != g_instances[inst$name]$listen_port ) )
			{
			# The endpoint looks different. We drop the current one
			# and need to re-establish connectivity.
			add insts_to_drop[inst$name];
			}
		}

	# Process our TODO lists.
	for ( inst_name in insts_to_drop )
		drop_instance(g_instances[inst_name]);

	for ( inst_name in insts_to_peer )
		add_instance(insts_to_peer[inst_name]);

	# XXX validate the configuration:
	# - Are node instances among defined instances?
	# - Are all names unique?
	# - Are any node options understood?
	# - Do node types with optional fields have required values?
	# ...

	# Track this config request globally until all of the agents required
	# for it have checked in.  It gets cleared in the notify_agents_ready
	# event handler.
	g_config_reqid_pending = req$id;

	# Special case: if the new request kept the set of instances identical,
	# trigger notify_agents_ready explicitly so we transmit the new config.
	if ( |insts_to_drop| == 0 && |insts_to_add| == 0 && |insts_to_keep| > 0 )
		event ClusterController::API::notify_agents_ready(insts_to_keep);
	}

event ClusterController::API::get_instances_request(reqid: string)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::set_instances_request %s", reqid));

	local res = ClusterController::Types::Result($reqid = reqid);
	local insts: vector of ClusterController::Types::Instance;

	for ( i in g_instances )
		insts += g_instances[i];

	res$data = insts;

	ClusterController::Log::info(fmt("tx ClusterController::API::get_instances_response %s", reqid));
	event ClusterController::API::get_instances_response(reqid, res);
	}

event ClusterController::Request::request_expired(req: ClusterController::Request::Request)
	{
	# Various handlers for timed-out request state. We use the state members
	# to identify how to respond.  No need to clean up the request itself,
	# since we're getting here via the request module's expiration
	# mechanism that handles the cleanup.
	local res: ClusterController::Types::Result;

	if ( req?$set_configuration_state )
		{
		res = ClusterController::Types::Result($reqid=req$id);
		res$success = F;
		res$error = "request timed out";
		req$results += res;

		ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s",
		                                 ClusterController::Request::to_string(req)));
		event ClusterController::API::set_configuration_response(req$id, req$results);
		}

	if ( req?$test_state )
		{
		res = ClusterController::Types::Result($reqid=req$id);
		res$success = F;
		res$error = "request timed out";

		ClusterController::Log::info(fmt("tx ClusterController::API::test_timeout_response %s", req$id));
		event ClusterController::API::test_timeout_response(req$id, res);
		}
	}

event ClusterController::API::test_timeout_request(reqid: string, with_state: bool)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::test_timeout_request %s %s", reqid, with_state));

	if ( with_state )
		{
		# This state times out and triggers a timeout response in the
		# above request_expired event handler.
		local req = ClusterController::Request::create(reqid);
		req$test_state = ClusterController::Request::TestState();
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

	local cni = ClusterController::network_info();

	Broker::listen(cat(cni$address), cni$bound_port);

	Broker::subscribe(ClusterAgent::topic_prefix);
	Broker::subscribe(ClusterController::topic);

	# Events sent to the client:

	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::get_instances_response);
	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::set_configuration_response);
	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::test_timeout_response);

	ClusterController::Log::info("controller is live");
	}
