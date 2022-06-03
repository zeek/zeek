# This test verifies basic agent-controller communication in the Management
# framework. We launch agent and controller via the supervisor, add an extra
# handler for the notify_agent_hello event that travels agent -> controller, and
# verify that it prints receipt of the event to stdout.

# The following environment variables are known to the controller framework:
# @TEST-PORT: ZEEK_CONTROLLER_PORT
# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: ZEEK_MANAGEMENT_TESTING=1 btest-bg-run zeek zeek -j %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/nodes/controller/stdout

@load policy/frameworks/management/agent
@load policy/frameworks/management/controller

redef Broker::default_port = to_port(getenv("BROKER_PORT"));

redef Management::Controller::name = "controller";
redef Management::Agent::name = "agent";

# Tell the agent where to locate the controller.
redef Management::Agent::controller = [$address="127.0.0.1", $bound_port=to_port(getenv("ZEEK_CONTROLLER_PORT"))];

@if ( Supervisor::is_supervised() )

@load policy/frameworks/management/agent/api

global logged = F;

event zeek_init()
	{
	# We're using the controller to shut everything down once the
	# notify_agent_hello event has arrived. The controller doesn't normally
	# talk to the supervisor, so connect to it.
	if ( Management::role == Management::CONTROLLER )
		{
		Broker::peer(getenv("ZEEK_DEFAULT_LISTEN_ADDRESS"), Broker::default_port, Broker::default_listen_retry);
		Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::stop_request);
		}
	}

event Management::Agent::API::notify_agent_hello(instance: string, id: string, connecting: bool, api_version: count)
	{
	if ( Management::role == Management::CONTROLLER )
		{
		if ( ! logged )
			print(fmt("notify_agent_hello %s %s", instance, api_version));

		logged = T;

		# This takes down the whole process tree.
		event SupervisorControl::stop_request();
		}
	}

@endif
