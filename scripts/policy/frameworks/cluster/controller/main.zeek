@load base/frameworks/broker

@load policy/frameworks/cluster/agent/config
@load policy/frameworks/cluster/agent/api

@load ./api
@load ./log
@load ./request

redef ClusterController::role = ClusterController::Types::CONTROLLER;

global config_current: ClusterController::Types::Configuration;
global config_reqid_pending: string = "";

function send_config_to_agents(req: ClusterController::Request::Request,
                               config: ClusterController::Types::Configuration)
	{
	for ( name in ClusterController::instances )
		{
		local agent_topic = ClusterAgent::topic_prefix + "/" + name;
		local areq = ClusterController::Request::create();
		areq$parent_id = req$id;

		# We track the requests sent off to each agent. As the
		# responses come in, we can check them off as completed,
		# and once all are, we respond back to the client.
		req$set_configuration_state$requests += areq;

		# XXX could also broadcast just once on the agent prefix, but
		# explicit request/response pairs for each agent seems cleaner.
		ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, ClusterAgent::API::set_configuration_request, areq$id, config);
		}
	}

function drop_instance(inst: ClusterController::Types::Instance)
	{
	if ( inst$name in ClusterController::instances )
		{
		# Send this agent a config that will terminate any data cluster
		# nodes it might have. This is "fire and forget" -- there will
		# not be a response.
		Broker::publish(ClusterAgent::topic_prefix + "/" + inst$name,
		                ClusterAgent::API::set_configuration_request,
		                "", ClusterController::Types::Configuration());

		delete ClusterController::instances[inst$name];
		}

	# If the instance has a port, we peered with it, so now unpeer.
	if ( inst?$listen_port )
		Broker::unpeer(cat(inst$host), inst$listen_port );

	ClusterController::Log::info(fmt("dropped instance %s", inst$name));
	}

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	# See if we already know about this agent; if not, register
	# it.
	#
	# XXX protection against rogue agents?

	local inst: ClusterController::Types::Instance;

	if ( instance in ClusterController::instances )
		{
		# Do nothing, unless this known agent checks in with a mismatching
		# API version, in which case we kick it out.
		if ( api_version != ClusterController::API::version )
			drop_instance(ClusterController::instances[instance]);

		# Update the instance name in the pointed-to record, in case it
		# was previously named otherwise. Not being too picky here allows
		# the user some leeway in spelling out the original config.
		ClusterController::instances[instance]$name = instance;
		return;
		}

	if ( api_version != ClusterController::API::version )
		{
		ClusterController::Log::warning(
		    fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s), ignoring",
		        instance, host, api_version, ClusterController::API::version));
		return;
		}

	ClusterController::instances[instance] = ClusterController::Types::Instance($name=instance, $host=host);
	ClusterController::Log::info(fmt("instance %s/%s has checked in", instance, host));

	# If we have a pending configuration request, check in on it now to see whether
	# we have all agents required, and finalize the config request.
	if ( config_reqid_pending == "" )
		return;

	local req = ClusterController::Request::lookup(config_reqid_pending);

	if ( ClusterController::Request::is_null(req) || ! req?$set_configuration_state )
		{
		# Odd, just clear out pending state.
		config_reqid_pending = "";
		return;
		}

	for ( inst in req$set_configuration_state$config$instances )
		{
		if ( inst$name !in ClusterController::instances )
			{
			# The request still has instances not known to us, try again
			# later.
			return;
			}
		}

	# All instances requested in the configuration are now known to us.
	# Send them the config. As they send their response events we
	# update the request state and eventually send the response event
	# to the client.
	send_config_to_agents(req, req$set_configuration_state$config);
	config_reqid_pending = "";
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
	if ( config_reqid_pending != "" )
		{
		res = ClusterController::Types::Result($reqid=reqid);
		res$success = F;
		res$error = fmt("request %s still pending", config_reqid_pending);
		req$results += res;

		ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s",
		                                 ClusterController::Request::to_string(req)));
		event ClusterController::API::set_configuration_response(req$id, req$results);
		ClusterController::Request::finish(req$id);
		return;
		}

	# Compare the instance configuration to our current one. For instances
	# that are supposed to be checking in with us but have not, record
	# errors. We will fail the request in those cases. For instances we
	# don't know and are supposed to connect to, do so next.
	local inst_name: string;
	local inst: ClusterController::Types::Instance;
	local insts_to_add: ClusterController::Types::InstanceVec;

	# A set of instances not contained in the config, that therefore needs
	# to be dropped.
	local insts_to_drop: set[string] = {};

	for ( inst_name in ClusterController::instances )
		add insts_to_drop[inst_name];

	for ( inst in config$instances )
		{
		if ( inst$name in ClusterController::instances )
			{
			# Verify that it's actually the same endpoint. If not, kick out
			# the old one. XXX 0.0.0.0 is a workaround until we've resolved
			# how agents that peer with us obtain their identity.
			if ( ( inst$host != 0.0.0.0 && inst$host != ClusterController::instances[inst$name]$host ) ||
			     inst?$listen_port != ClusterController::instances[inst$name]?$listen_port ||
			     ( inst?$listen_port && ClusterController::instances[inst$name]?$listen_port &&
			       inst$listen_port != ClusterController::instances[inst$name]$listen_port ) )
				{
				drop_instance(ClusterController::instances[inst$name]);
				}
			else
				{
				# We know this instance, don't drop it below.
				delete insts_to_drop[inst$name];
				}
			}

		if ( inst$name !in ClusterController::instances )
			{
			# It's an instance we don't currently know about.
			if ( ! inst?$listen_port )
				{
				# If a requested instance doesn't have a listen port and isn't known
				# to us, we have no way to establish connectivity. We reject the
				# request.
				res = ClusterController::Types::Result($reqid=reqid, $instance=inst$name);
				res$success = F;
				res$error = fmt("instance %s is unknown", inst$name);
				req$results += res;
				}
			else
				{
				# We'll need to connect to this instance.
				insts_to_add[|insts_to_add|] = inst;
				}
			}
		}

	# An error at this point means that we're rejecting this request.
	if ( |req$results| > 0 )
		{
		ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s",
		                                 ClusterController::Request::to_string(req)));
		event ClusterController::API::set_configuration_response(req$id, req$results);
		ClusterController::Request::finish(req$id);
		return;
		}

	for ( inst_name in insts_to_drop )
		drop_instance(ClusterController::instances[inst_name]);

	# We have instances to connect to, so initiate peering and stop for now.
	# Processing will continue as the agents check in. That's also when they
	# get added to ClusterController::instances.
	if ( |insts_to_add| > 0 )
		{
		for ( idx in insts_to_add )
			{
			inst = insts_to_add[idx];
			Broker::peer(cat(inst$host), inst$listen_port,
			             ClusterController::connect_retry);
			}

		config_reqid_pending = req$id;
		return;
		}

	# XXX validate the configuration:
	# - Are node instances among defined instances?
	# - Are all names unique?
	# - Are any node options understood?
	# - Do node types with optional fields have required values?
	# ...

	# Response event gets sent via the agents' reponse event.
	send_config_to_agents(req, config);
	}

event ClusterController::API::get_instances_request(reqid: string)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::set_instances_request %s", reqid));

	local insts: vector of ClusterController::Types::Instance;

	for ( i in ClusterController::instances )
		insts += ClusterController::instances[i];

	ClusterController::Log::info(fmt("tx ClusterController::API::get_instances_response %s", reqid));
	event ClusterController::API::get_instances_response(reqid, insts);
	}

event zeek_init()
	{
	# Controller always listens -- it needs to be able to respond
	# to the Zeek client. This port is also used by the agents
	# if they connect to the client.
	local cni = ClusterController::network_info();
	Broker::listen(cat(cni$address), cni$bound_port);

	Broker::subscribe(ClusterAgent::topic_prefix);
	Broker::subscribe(ClusterController::topic);

	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::get_instances_response);
	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::set_configuration_response);

	if ( |ClusterController::instances| > 0 )
		{
		# We peer with the agents -- otherwise, the agents peer
		# with (i.e., connect to) us.
		for ( i in ClusterController::instances )
			{
			local inst = ClusterController::instances[i];

			if ( ! inst?$listen_port )
				{
				# XXX config error -- this must be there
				next;
				}

			Broker::peer(cat(inst$host), inst$listen_port,
			             ClusterController::connect_retry);
			}
		}

	# If ClusterController::instances is empty, agents peer with
	# us and we do nothing. We'll build up state as the
	# notify_agent_hello() events come int.

	ClusterController::Log::info("controller is live");
	}
