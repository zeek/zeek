##! The Management event API of cluster nodes. The API consists of request/
##! response event pairs, like elsewhere in the Management, Supervisor, and
##! Control frameworks.

@load policy/frameworks/management/types

module Management::Node::API;

export {
	## Management agents send this event to every Zeek cluster node to run a
	## "dispatch" -- a particular, pre-implemented action. This is the agent-node
	## complement to :zeek:see:`Management::Agent::API::node_dispatch_request`.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## action: the requested dispatch command, with any arguments.
	##
	## nodes: the cluster node names this dispatch targets. An empty set,
	##     supplied by default, means it applies to all nodes. Since nodes
	##     receive all dispatch requests, they can use any node names provided
	##     here to filter themselves out of responding.
	global node_dispatch_request: event(reqid: string, action: vector of string,
	    nodes: set[string] &default=set());

	## Response to a node_dispatch_request event. The nodes send this back
	## to the agent. This is the agent-node equivalent of
	## :zeek:see:`Management::Agent::API::node_dispatch_response`.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:see:`Management::Result` record covering one Zeek
	##     cluster node managed by the agent. Upon success, the data field
	##     contains a value appropriate for the requested dispatch.
	global node_dispatch_response: event(reqid: string, result: Management::Result);


	# Notification events, node -> agent

	## The cluster nodes send this event upon peering as a "check-in" to
	## the agent, to indicate the node is now available to communicate
	## with. It is an agent-level equivalent of :zeek:see:`Broker::peer_added`,
	## and similar to :zeek:see:`Management::Agent::API::notify_agent_hello`
	## for agents.
	##
	## node: the name of the node, as given in :zeek:see:`Cluster::node`.
	##
	global notify_node_hello: event(node: string);
}
