##! The event API of cluster controllers. Most endpoints consist of event pairs,
##! where the controller answers a zeek-client request event with a
##! corresponding response event. Such event pairs share the same name prefix
##! and end in "_request" and "_response", respectively.

@load policy/frameworks/management/types

module Management::Controller::API;

export {
	## A simple versioning scheme, used to track basic compatibility of
	## controller, agents, and zeek-client.
	const version = 1;


	## zeek-client sends this event to request a list of the currently
	## peered agents/instances.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global get_instances_request: event(reqid: string);

	## Response to a get_instances_request event. The controller sends
	## this back to the client.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record. Its data member is a
	##     :zeek:see:`Management::Instance` record.
	##
	global get_instances_response: event(reqid: string,
	    result: Management::Result);


	## zeek-client sends this event to establish a new cluster configuration,
	## including the full cluster topology. The controller processes the update
	## and relays it to the agents. Once each has responded (or a timeout occurs)
	## the controller sends a corresponding response event back to the client.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## config: a :zeek:see:`Management::Configuration` record
	##     specifying the cluster configuration.
	##
	global set_configuration_request: event(reqid: string,
	    config: Management::Configuration);

	## Response to a set_configuration_request event. The controller sends
	## this back to the client.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a vector of :zeek:see:`Management::Result` records.
	##     Each member captures one agent's response.
	##
	global set_configuration_response: event(reqid: string,
	    result: Management::ResultVec);


	## zeek-client sends this event to request a list of
	## :zeek:see:`Management::NodeStatus` records that capture
	## the status of Supervisor-managed nodes running on the cluster's
	## instances.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global get_nodes_request: event(reqid: string);

	## Response to a get_nodes_request event. The controller sends this
	## back to the client.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:type:`vector` of :zeek:see:`Management::Result`
	##     records. Each record covers one cluster instance. Each record's data
	##     member is a vector of :zeek:see:`Management::NodeStatus`
	##     records, covering the nodes at that instance. Results may also indicate
	##     failure, with error messages indicating what went wrong.
	global get_nodes_response: event(reqid: string,
	    result: Management::ResultVec);


	## zeek-client sends this event to retrieve the current value of a
	## variable in Zeek's global namespace, referenced by the given
	## identifier (i.e., variable name). The controller asks all agents
	## to retrieve this value from each cluster node, accumulates the
	## returned responses, and responds with a get_id_value_response
	## event back to the client.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## id: the name of the variable whose value to retrieve.
	##
	## nodes: a set of cluster node names (e.g. "worker-01") to retrieve
	##    the values from. An empty set, supplied by default, means
	##    retrieval from all current cluster nodes.
	global get_id_value_request: event(reqid: string, id: string,
	    nodes: set[string] &default=set());

	## Response to a get_id_value_request event. The controller sends this
	## back to the client.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:type:`vector` of :zeek:see:`Management::Result`
	##     records. Each record covers one Zeek cluster node. Each record's
	##     data field contains a string with the JSON rendering (as produced
	##     by :zeek:id:`to_json`, including the error strings it potentially
	##     returns).
	global get_id_value_response: event(reqid: string, result: Management::ResultVec);


	# Testing events. These don't provide operational value but expose
	# internal functionality, triggered by test cases.

	## This event causes no further action (other than getting logged) if
	## with_state is F. When T, the controller establishes request state, and
	## the controller only ever sends the response event when this state times
	## out.
	##
	## reqid: a request identifier string, echoed in the response event when
	##     with_state is T.
	##
	## with_state: flag indicating whether the controller should keep (and
	##     time out) request state for this request.
	##
	global test_timeout_request: event(reqid: string, with_state: bool);

	## Response to a test_timeout_request event. The controller sends this
	## back to the client if the original request had the with_state flag.
	##
	## reqid: the request identifier used in the request event.
	##
	global test_timeout_response: event(reqid: string,
	    result: Management::Result);


	# Notification events

	## The controller triggers this event when the operational cluster
	## instances align with the ones desired by the cluster
	## configuration. It's essentially a cluster management readiness
	## event. This event is currently only used by the controller and not
	## published to other topics.
	##
	## instances: the set of instance names now ready.
	##
	global notify_agents_ready: event(instances: set[string]);
	}
