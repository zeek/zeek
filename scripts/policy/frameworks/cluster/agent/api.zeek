@load base/frameworks/supervisor/control
@load policy/frameworks/cluster/controller/types

module ClusterAgent::API;

export {
	const version = 1;

	# Agent API events

	global set_configuration_request: event(reqid: string,
	    config: ClusterController::Types::Configuration);
	global set_configuration_response: event(reqid: string,
	    result: ClusterController::Types::Result);

	# Notification events, agent -> controller

	# Report agent being available.
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

	# Notification events, controller -> agent

	# Confirmation from controller in response to notify_agent_hello
	# that the agent is welcome.
	global notify_controller_hello: event(controller: string, host: addr);

}
