##! The event API of cluster controllers. Most endpoints consist of event pairs,
##! where the controller answers the client's request event with a corresponding
##! response event. Such event pairs share the same name prefix and end in
##! "_request" and "_response", respectively.

@load policy/frameworks/management/types

module Management::Controller::API;

export {
	## A simple versioning scheme, used to track basic compatibility of
	## controller, agents, and the client.
	const version = 1;


	## The client sends this event to request a list of the currently
	## peered agents/instances.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global get_instances_request: event(reqid: string);

	## Response to a
	## :zeek:see:`Management::Controller::API::get_instances_request`
	## event. The controller sends this back to the client.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:see:`Management::Result`. Its data member is a vector
	##     of :zeek:see:`Management::Instance` records.
	##
	global get_instances_response: event(reqid: string,
	    result: Management::Result);


	## Upload a configuration to the controller for later deployment.
	## The client sends this event to the controller, which validates the
	## configuration and indicates the outcome in its response event. No
	## deployment takes place yet, and existing deployed configurations and
	## the running Zeek cluster remain intact. To trigger deployment of an uploaded
	## configuration, use :zeek:see:`Management::Controller::API::deploy_request`.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## config: a :zeek:see:`Management::Configuration` record
	##     specifying the cluster configuration.
	##
	global stage_configuration_request: event(reqid: string,
	    config: Management::Configuration);

	## Response to a
	## :zeek:see:`Management::Controller::API::stage_configuration_request`
	## event. The controller sends this back to the client, conveying
	## validation results.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:see:`Management::Result` vector, indicating whether
	##     the controller accepts the configuration. In case of a success,
	##     a single result record indicates so. Otherwise, the sequence is
	##     all errors, each indicating a configuration validation error.
	##
	global stage_configuration_response: event(reqid: string,
	    results: Management::ResultVec);


	## The client sends this event to retrieve the controller's current
	## cluster configuration(s).
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## deployed: when true, returns the deployed configuration (if any),
	##     otherwise the staged one (if any).
	##
	global get_configuration_request: event(reqid: string, deployed: bool);

	## Response to a
	## :zeek:see:`Management::Controller::API::get_configuration_request`
	## event. The controller sends this back to the client, with the
	## requested configuration.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:see:`Management::Result` record with a successful
	##     :zeek:see:`Management::Configuration` in the data member, if
	##     a configuration is currently deployed. Otherwise, a Result
	##     record in error state, with no data value assigned.
	##
	global get_configuration_response: event(reqid: string,
	    result: Management::Result);


	## Trigger deployment of a previously staged configuration.  The client
	## sends this event to the controller, which deploys the configuration
	## to the agents. Agents then terminate any previously running cluster
	## nodes and (re-)launch those defined in the new configuration. Once
	## each agent has responded (or a timeout occurs), the controller sends
	## a response event back to the client, aggregating the results from the
	## agents. The controller keeps the staged configuration available for
	## download, or re-deployment.  In addition, the deployed configuration
	## becomes available for download as well, with any augmentations
	## (e.g. node ports filled in by auto-assignment) reflected.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global deploy_request: event(reqid: string);

	## Response to a :zeek:see:`Management::Controller::API::deploy_request`
	## event. The controller sends this back to the client, conveying the
	## outcome of the deployment.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a vector of :zeek:see:`Management::Result` records.
	##     Each member captures the result of launching one cluster
	##     node captured in the configuration, or an agent-wide error
	##     when the result does not indicate a particular node.
	##
	global deploy_response: event(reqid: string,
	    results: Management::ResultVec);


	## The client sends this event to request a list of
	## :zeek:see:`Management::NodeStatus` records that capture
	## the status of Supervisor-managed nodes running on the cluster's
	## instances.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global get_nodes_request: event(reqid: string);

	## Response to a
	## :zeek:see:`Management::Controller::API::get_nodes_request` event. The
	## controller sends this back to the client, with a description of the
	## nodes currently managed by the Supervisors on all connected
	## instances. This includes agents and possibly the controller, if it
	## runs jointly with an agent.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
	##     records. Each record covers one cluster instance. Each record's
	##     data member is a vector of :zeek:see:`Management::NodeStatus`
	##     records, covering the nodes at that instance. Results may also
	##     indicate failure, with error messages indicating what went wrong.
	##
	global get_nodes_response: event(reqid: string,
	    results: Management::ResultVec);


	## The client sends this event to retrieve the current value of a
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
	##
	global get_id_value_request: event(reqid: string, id: string,
	    nodes: set[string] &default=set());

	## Response to a
	## :zeek:see:`Management::Controller::API::get_id_value_request`
	## event. The controller sends this back to the client, with a JSON
	## representation of the requested global ID on all relevant instances.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
	##     records. Each record covers one Zeek cluster node. Each record's
	##     data field contains a string with the JSON rendering (as produced
	##     by :zeek:id:`to_json`, including the error strings it potentially
	##     returns).
	##
	global get_id_value_response: event(reqid: string, results: Management::ResultVec);


	## The client sends this event to restart currently running Zeek cluster
	## nodes. The controller relays the request to its agents, which respond
	## with a list of :zeek:see:`Management::Result` records summarizing
	## each node restart. The controller combines these lists, and sends a
	## :zeek:see:`Management::Controller::API::restart_response` event with
	## the result.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## nodes: a set of cluster node names (e.g. "worker-01") to restart.  An
	##    empty set, supplied by default, means restart of all current
	##    cluster nodes.
	##
	global restart_request: event(reqid: string, nodes: set[string] &default=set());

	## Response to a :zeek:see:`Management::Controller::API::restart_request`
	## event. The controller sends this back to the client when it has received
	## responses from all agents involved, or a timeout occurs.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:type:`vector` of :zeek:see:`Management::Result`,
	##     combining the restart results from all agents. Each such result
	##     identifies both the instance and node in question. Results that
	##     do not identify an instance are generated by the controller,
	##     flagging corner cases, including absence of a deployed cluster
	##     or unknown nodes.
	##
	global restart_response: event(reqid: string, results: Management::ResultVec);

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

	## Response to a
	## :zeek:see:`Management::Controller::API::test_timeout_request`
	## event. The controller sends this back to the client if the original
	## request had the with_state flag.
	##
	## reqid: the request identifier used in the request event.
	##
	global test_timeout_response: event(reqid: string,
	    result: Management::Result);


	# Notification events

	## The controller triggers this event when the operational cluster
	## instances align with the ones desired by the cluster
	## configuration. It's essentially a cluster management readiness
	## event. This event is currently only used internally by the controller,
	## and not published to topics.
	##
	## instances: the set of instance names now ready.
	##
	global notify_agents_ready: event(instances: set[string]);
}
