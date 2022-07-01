##! Configuration settings for the Management framework's supervisor extension.

module Management::Supervisor;

export {
	## The Broker topic for Management framework communication with the
	## Supervisor. The agent subscribes to this.
	const topic_prefix = "zeek/management/supervisor" &redef;

	## Whether to print the stdout sent up to the Supervisor by created
	## nodes to the terminal. By default, this is disabled since this output
	## already ends up in a node-specific stdout file, per
	## :zeek:see:`Management::Node::stdout_file`.
	const print_stdout = F &redef;

	## Whether to print the stderr sent up to the Supervisor by created
	## nodes to the terminal. By default, this is disabled since this output
	## already ends up in a node-specific stderr file, per
	## :zeek:see:`Management::Node::stderr_file`.
	const print_stderr = F &redef;

	## The maximum number of stdout/stderr output lines to convey in
	## :zeek:see:`Management::Supervisor::API::notify_node_exit` events.
	const output_max_lines: count = 100 &redef;
}
