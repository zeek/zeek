##! Configuration settings for the Management framework's supervisor extension.

module Management::Supervisor;

export {
	## The Broker topic for Management framework communication with the
	## Supervisor. The agent subscribes to this.
	const topic_prefix = "zeek/management/supervisor" &redef;

	## The maximum number of stdout/stderr output lines to convey in
	## :zeek:see:`Management::Supervisor::API::notify_node_exit` events.
	const output_max_lines: count = 100 &redef;
}
