##! The event API of cluster agents. Most endpoints consist of event pairs,
##! where the agent answers a request event with a corresponding response
##! event. Such event pairs share the same name prefix and end in "_request" and
##! "_response", respectively.

@load base/frameworks/supervisor/control
@load policy/frameworks/cluster/controller/types

module ClusterAgent::API;

export {
	## A simple versioning scheme, used to track basic compatibility of
	## controller and agent.
	const version = 1;


	# Agent API events

	## The controller sends this event to convey a new cluster configuration
	## to the agent. Once processed, the agent responds with the response
	## event.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## config: a :zeek:see:`ClusterController::Types::Configuration` record
	##     describing the cluster topology. Note that this contains the full
	##     topology, not just the part pertaining to this agent. That's because
	##     the cluster framework requires full cluster visibility to establish
	##     the needed peerings.
	##
	global set_configuration_request: event(reqid: string,
	    config: ClusterController::Types::Configuration);

	## Response to a set_configuration_request event. The agent sends
	## this back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record.
	##
	global set_configuration_response: event(reqid: string,
	    result: ClusterController::Types::Result);


	## The controller sends this event to confirm to the agent that it is
	## part of the current cluster topology. The agent acknowledges with the
	## corresponding response event.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	global agent_welcome_request: event(reqid: string);

	## Response to an agent_welcome_request event. The agent sends this
	## back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record.
	##
	global agent_welcome_response: event(reqid: string,
	    result: ClusterController::Types::Result);


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

	## Response to an agent_standby_request event. The agent sends this
	## back to the controller.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: the result record.
	##
	global agent_standby_response: event(reqid: string,
	    result: ClusterController::Types::Result);


	# Notification events, agent -> controller

	## The agent sends this event upon peering as a "check-in", informing
	## the controller that an agent of the given name is now available to
	## communicate with. It is a controller-level equivalent of
	## `:zeek:see:`Broker::peer_added`.
	##
	## instance: an instance name, really the agent's name as per :zeek:see:`ClusterAgent::name`.
	##
	## host: the IP address of the agent. (This may change in the future.)
	##
	## api_version: the API version of this agent.
	##
	global notify_agent_hello: event(instance: string, host: addr,
	    api_version: count);


	# The following are not yet implemented.

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
