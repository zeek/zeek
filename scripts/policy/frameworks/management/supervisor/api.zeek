@load policy/frameworks/management/types

module Management::Supervisor::API;

export {
	## The Supervisor generates this event whenever it has received a status
	## update from the stem, indicating that a node exited.
	##
	## node: the name of a node previously created via
	##     :zeek:see:`Supervisor::create`.
	##
	## outputs: stdout/stderr context for the node. The contained strings
	##     span up to the 100 most recent lines in the corresponding
	##     stream. See :zeek:see:`Management::Supervisor::output_max_lines`
	##     to adjust the line limit.
	##
	global notify_node_exit: event(node: string, outputs: Management::NodeOutputs);
}
