@load base/frameworks/broker

@load policy/frameworks/cluster/agent/config
@load policy/frameworks/cluster/agent/api

@load ./api
@load ./log
@load ./request

redef ClusterController::role = ClusterController::Types::CONTROLLER;

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	# See if we already know about this agent; if not, register
	# it.
	#
	# XXX protection against rogue agents?

	if ( instance in ClusterController::instances )
		{
		# Do nothing, unless this known agent checks in with a mismatching
		# API version, in which case we kick it out.
		if ( api_version != ClusterController::API::version )
			{
			local inst = ClusterController::instances[instance];
			if ( inst?$listen_port )
				{
				# We peered with this instance, unpeer.
				Broker::unpeer(cat(inst$host), inst$listen_port );
				# XXX what to do if they connected to us?
				}
			delete ClusterController::instances[instance];
			}

		# Update the instance name in the pointed-to record, in case it
		# was previously named otherwise. Not being too picky here allows
		# the user some leeway in spelling out the original config.
		ClusterController::instances[instance]$name = instance;

		return;
		}

	if ( api_version != ClusterController::API::version )
		{
		ClusterController::Log::warning(
		    fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s), unpeering",
		        instance, host, api_version, ClusterController::API::version));
		}

	ClusterController::instances[instance] = ClusterController::Types::Instance($name=instance, $host=host);
	ClusterController::Log::info(fmt("instance %s/%s has checked in", instance, host));
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

	ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s", req$id));
	event ClusterController::API::set_configuration_response(req$id, req$results);
	ClusterController::Request::finish(req$id);
	}

event ClusterController::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::set_configuration_request %s", reqid));

	local req = ClusterController::Request::create(reqid);
	req$set_configuration_state = ClusterController::Request::SetConfigurationState();

	# Compare new configuration to the current one and send updates
	# to the instances as needed.
	if ( config?$instances )
		{
		# XXX properly handle instance update: connect to new instances provided
		# when they are listening, accept connections from new instances that are
		# not
		for ( inst in config$instances )
			{
			if ( inst$name !in ClusterController::instances )
				{
				local res = ClusterController::Types::Result($reqid=reqid, $instance=inst$name);
				res$error = fmt("instance %s is unknown, skipping", inst$name);
				req$results += res;
				}
			}
		}

	# XXX validate the configuration:
	# - Are node instances among defined instances?
	# - Are all names unique?
	# - Are any node options understood?
	# - Do node types with optional fields have required values?
	# ...

	# Transmit the configuration on to the agents. They need to be aware of
	# each other's location and nodes, so the data cluster nodes can connect
	# (for example, so a worker on instance 1 can connect to a logger on
	# instance 2).
	for ( name in ClusterController::instances )
		{
		local agent_topic = ClusterAgent::topic_prefix + "/" + name;
		local areq = ClusterController::Request::create();
		areq$parent_id = reqid;

		# We track the requests sent off to each agent. As the
		# responses come in, we can check them off as completed,
		# and once all are, we respond back to the client.
		req$set_configuration_state$requests += areq;

		# XXX could also broadcast just once on the agent prefix, but
		# explicit request/response pairs for each agent seems cleaner.
		ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_request %s to %s",
		                                 areq$id, name));
		Broker::publish(agent_topic, ClusterAgent::API::set_configuration_request, areq$id, config);
		}

	# Response event gets sent via the agents' reponse event.
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
