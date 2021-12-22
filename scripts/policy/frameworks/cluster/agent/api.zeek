@load base/frameworks/supervisor/control
@load policy/frameworks/cluster/controller/types

module ClusterAgent::API;

export {
	const version = 1;

	# Agent API events

	# The controller uses this event to convey a new cluster
	# configuration to the agent. Once processed, the agent
	# responds with the response event.
	global set_configuration_request: event(reqid: string,
	    config: ClusterController::Types::Configuration);
	global set_configuration_response: event(reqid: string,
	    result: ClusterController::Types::Result);

	# The controller uses this event to confirm to the agent
	# that it is part of the current cluster. The agent
	# acknowledges with the response event.
	global agent_welcome_request: event(reqid: string);
	global agent_welcome_response: event(reqid: string,
	    result: ClusterController::Types::Result);

	# The controller sends this event to convey that the agent is not
	# currently required. This status may later change, depending on
	# updates from the client, so the peering can remain active. The
	# agent releases any cluster-related resources when processing the
	# request.
	global agent_standby_request: event(reqid: string);
	global agent_standby_response: event(reqid: string,
	    result: ClusterController::Types::Result);

	# Notification events, agent -> controller

	# The agent sends this upon peering as a "check in", informing the
	# controller that an agent of the given name is now available to
	# communicate with.
	global notify_agent_hello: event(instance: string, host: addr,
	    api_version: count);

	# Report node state changes.
	global notify_change: event(instance: string,
	    n: ClusterController::Types::Node,
	    old: ClusterController::Types::State,
	    new: ClusterController::Types::State);

	# Report operational error.
	global notify_error: event(instance: string, msg: string, node: string &default="");

	# Report informational message.
	global notify_log: event(instance: string, msg: string, node: string &default="");
}
