##! Configuration settings for nodes controlled by the Management framework.

module Management::Node;

export {
	## The nodes' Broker topic. Cluster nodes automatically subscribe
	## to it, to receive request events from the Management framework.
	const node_topic = "zeek/management/node" &redef;

	## Cluster node stdout log configuration. If the string is non-empty,
	## Zeek will produce a free-form log (i.e., not one governed by Zeek's
	## logging framework) in the node's working directory. If left empty, no
	## such log results.
	##
	## Note that cluster nodes also establish a "proper" management log via
	## the :zeek:see:`Management::Log` module.
	const stdout_file = "stdout" &redef;

	## Cluster node stderr log configuration. Like
	## :zeek:see:`Management::Node::stdout_file`, but for the stderr stream.
	const stderr_file = "stderr" &redef;
}
