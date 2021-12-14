@load ./types

module ClusterController::API;

export {
	const version = 1;

	# Triggered when the operational instances align with desired ones, as
	# defined by the latest cluster config sent by the client.
	global notify_agents_ready: event(instances: set[string]);

	global get_instances_request: event(reqid: string);
	global get_instances_response: event(reqid: string,
	    result: ClusterController::Types::Result);

	global set_configuration_request: event(reqid: string,
	    config: ClusterController::Types::Configuration);
	global set_configuration_response: event(reqid: string,
	    result: ClusterController::Types::ResultVec);

	# Testing events. These don't provide operational value but expose
	# internal functionality, triggered by test cases.

	# This event causes no further action (other than getting logged) if
	# set_state is F. When T, the controller establishes request state. The
	# conroller only ever sends the response event when this state times
	# out.
	global test_timeout_request: event(reqid: string, with_state: bool);
	global test_timeout_response: event(reqid: string,
	    result: ClusterController::Types::Result);
	}
