##! The Management event API of cluster nodes. The API consists of request/
##! response event pairs, like elsewhere in the Management, Supervisor, and
##! Control frameworks.

@load policy/frameworks/management/types

module Management::Node::API;

export {
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
