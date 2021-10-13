# This test verifies basic agent-controller communication. We launch agent and
# controller via the supervisor, add an extra handler for the notify_agent_hello
# event that travels agent -> controller, and verify its print output in the
# controller's stdout log.

# The following env vars is known to the controller framework
# @TEST-PORT: ZEEK_CONTROLLER_PORT
# @TEST-PORT: BROKER_PORT

# A bit of a detour to get the port number into the agent configuration
# @TEST-EXEC: btest-bg-run zeek zeek -j %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/controller.stdout

@load policy/frameworks/cluster/agent
@load policy/frameworks/cluster/controller

redef Broker::default_port = to_port(getenv("BROKER_PORT"));

redef ClusterController::name = "controller";
redef ClusterAgent::name = "agent";

# Tell the agent where to locate the controller.
redef ClusterAgent::controller = [$address="127.0.0.1", $bound_port=to_port(getenv("ZEEK_CONTROLLER_PORT"))];

@if ( Supervisor::is_supervised() )

@load policy/frameworks/cluster/agent/api

global logged = F;

event zeek_init()
	{
	# We're using the controller to shut everything down once the
	# notify_agent_hello event has arrived. The controller doesn't normally
	# talk to the supervisor, so connect to it.
	if ( Supervisor::node()$name == "controller" )
		{
		Broker::peer(getenv("ZEEK_DEFAULT_LISTEN_ADDRESS"), Broker::default_port, Broker::default_listen_retry);
		Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::stop_request);
		}
	}

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	if ( Supervisor::node()$name == "controller" )
		{
		# On rare occasion it can happen that we log this twice, which'll need
		# investigating. For now we ensure we only do so once.
		if ( ! logged )
			print(fmt("notify_agent_hello %s %s %s", instance, host, api_version));

		logged = T;

		# This takes down the whole process tree.
		event SupervisorControl::stop_request();
		}
	}

@endif
