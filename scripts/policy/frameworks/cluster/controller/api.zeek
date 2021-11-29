@load ./types

module ClusterController::API;

export {
	const version = 1;

	# Triggered when the operational instances align with desired ones, as
	# defined by the latest cluster config sent by the client.
	global notify_agents_ready: event(instances: set[string]);

	global get_instances_request: event(reqid: string);
	global get_instances_response: event(reqid: string,
	    instances: vector of ClusterController::Types::Instance);

	global set_configuration_request: event(reqid: string,
	    config: ClusterController::Types::Configuration);
	global set_configuration_response: event(reqid: string,
	    result: ClusterController::Types::ResultVec);
}
