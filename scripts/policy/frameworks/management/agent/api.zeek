##! The event API of cluster agents. Most endpoints consist of event pairs,
##! where the agent answers a request event with a corresponding response
##! event. Such event pairs share the same name prefix and end in "_request" and
##! "_response", respectively.

@load base/frameworks/supervisor/control
@load policy/frameworks/management/types

module Management::Agent::API;

export {
	## A simple versioning scheme, used to track basic compatibility of
	## controller and agent.
	const version = 1;

	# Agent API events

	## The controller sends this event to deploy a cluster configuration to
	## this instance. Once processed, the agent responds with a
	## :zeek:see:`Management::Agent::API::deploy_response` event.  event.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## config: a :zeek:see:`Management::Configuration` record describing the
	##     cluster topology. This contains the full topology, not just the
	##     part pertaining to this instance: the cluster framework requires
	##     full cluster visibility to establish needed peerings.
	##
	## force: whether to re-deploy (i.e., restart its Zeek cluster nodes)
	##     when the agent already runs this configuration. This relies on
	##     the config ID to determine config equality.
	##
	global deploy_request: event(reqid: string,
	    config: Management::Configuration, force: bool &default=F);

	## Response to a :zeek:see:`Management::Agent::API::deploy_request`
	## event. The agent sends this back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: A vector of :zeek:see:`Management::Result` records, each
	##     capturing the outcome of a single launched node. For failing
	##     nodes, the result's data field is a
	##     :zeek:see:`Management::NodeOutputs` record.
	##
	global deploy_response: event(reqid: string,
	    results: Management::ResultVec);


	## The controller sends this event to request a list of
	## :zeek:see:`Management::NodeStatus` records that capture
	## the status of Supervisor-managed nodes running on this instance.
	## instances.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global get_nodes_request: event(reqid: string);

	## Response to a :zeek:see:`Management::Agent::API::get_nodes_request`
	## event. The agent sends this back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:see:`Management::Result` record. Its data
	##     member is a vector of :zeek:see:`Management::NodeStatus`
	##     records, covering the nodes at this instance. The result may also
	##     indicate failure, with error messages indicating what went wrong.
	##
	global get_nodes_response: event(reqid: string, result: Management::Result);


	## The controller sends this to every agent to request a dispatch (the
	## execution of a pre-implemented activity) to all cluster nodes.  This
	## is the generic controller-agent "back-end" implementation of explicit
	## client-controller "front-end" interactions, including:
	##
	## - :zeek:see:`Management::Controller::API::get_id_value_request`: two
	##   arguments, the first being "get_id_value" and the second the name
	##   of the ID to look up.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## action: the requested dispatch command, with any arguments.
	##
	## nodes: a set of cluster node names (e.g. "worker-01") to retrieve
	##    the values from. An empty set, supplied by default, means
	##    retrieval from all nodes managed by the agent.
	##
	global node_dispatch_request: event(reqid: string, action: vector of string,
	    nodes: set[string] &default=set());

	## Response to a
	## :zeek:see:`Management::Agent::API::node_dispatch_request` event. Each
	## agent sends this back to the controller to report the dispatch
	## outcomes on all nodes managed by that agent.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:type:`vector` of :zeek:see:`Management::Result`
	##     records. Each record covers one Zeek cluster node managed by this
	##     agent. Upon success, each :zeek:see:`Management::Result` record's
	##     data member contains the dispatches' response in a data type
	##     appropriate for the respective dispatch.
	##
	global node_dispatch_response: event(reqid: string, results: Management::ResultVec);


	## The controller sends this event to confirm to the agent that it is
	## part of the current cluster topology. The agent acknowledges with a
	## :zeek:see:`Management::Agent::API::agent_welcome_response` event,
	## upon which the controller may proceed with a cluster deployment to
	## this agent.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global agent_welcome_request: event(reqid: string);

	## Response to a
	## :zeek:see:`Management::Agent::API::agent_welcome_request` event. The
	## agent sends this back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record.
	##
	global agent_welcome_response: event(reqid: string,
	    result: Management::Result);


	## The controller sends this event to convey that the agent is not
	## currently required. This status may later change, depending on
	## updates from the client, so the Broker-level peering can remain
	## active. The agent releases any cluster-related resources (including
	## shutdown of existing Zeek cluster nodes) when processing the request,
	## and confirms via the response event. Shutting down an agent at this
	## point has no operational impact on the running cluster.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global agent_standby_request: event(reqid: string);

	## Response to a
	## :zeek:see:`Management::Agent::API::agent_standby_request` event. The
	## agent sends this back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record.
	##
	global agent_standby_response: event(reqid: string,
	    result: Management::Result);


	## The controller sends this event to ask the agent to restart currently
	## running Zeek cluster nodes. For nodes currently running, the agent
	## places these nodes into PENDING state and sends restart events to the
	## Supervisor, rendering its responses into a list of
	## :zeek:see:`Management::Result` records summarizing each node restart.
	## When restarted nodes check in with the agent, they switch back to
	## RUNNING state. The agent ignores nodes not currently running.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## nodes: a set of cluster node names (e.g. "worker-01") to restart. An
	##    empty set, supplied by default, means restart of all of the
	##    agent's current cluster nodes.
	##
	global restart_request: event(reqid: string, nodes: set[string] &default=set());

	## Response to a :zeek:see:`Management::Agent::API::restart_request`
	## event. The agent sends this back to the controller when the
	## Supervisor has restarted all nodes affected, or a timeout occurs.
	##
	## reqid: the request identifier used in the request event.
	##
	## results: a :zeek:type:`vector` of :zeek:see:`Management::Result`, one
	##     for each Supervisor transaction. Each such result identifies both
	##     the instance and node.
	##
	global restart_response: event(reqid: string, results: Management::ResultVec);


	# Notification events, agent -> controller

	## The agent sends this event upon peering as a "check-in", informing
	## the controller that an agent of the given name is now available to
	## communicate with. It is a controller-level equivalent of
	## `:zeek:see:`Broker::peer_added` and triggered by it.
	##
	## instance: an instance name, really the agent's name as per
	##    :zeek:see:`Management::Agent::get_name`.
	##
	## id: the Broker ID of the agent.
	##
	## connecting: true if this agent connected to the controller,
	##    false if the controller connected to the agent.
	##
	## api_version: the API version of this agent.
	##
	global notify_agent_hello: event(instance: string, id: string,
	    connecting: bool, api_version: count);


	# The following are not yet meaningfully implemented.

	# Report node state changes.
	global notify_change: event(instance: string,
	    n: Management::Node,
	    old: Management::State,
	    new: Management::State);

	# Report operational error.
	global notify_error: event(instance: string, msg: string, node: string &default="");

	# Report informational message.
	global notify_log: event(instance: string, msg: string, node: string &default="");
}
