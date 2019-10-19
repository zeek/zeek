##! The Zeek process supervision API.
# TODO: add proper docs

module Supervisor;

export {
	type Node: record {
		# TODO: add proper config fields
		name: string;
		pid: count &optional;
	};

	type Status: record {
		# TODO: add more status fields ?
		nodes: table[string] of Node;
	};

	global status: function(nodes: string &default="all"): Status;
	global create: function(node: Node): string;
	global destroy: function(nodes: string): bool;
	global restart: function(nodes: string &default="all"): bool;

	global Supervisor::stop_request: event();

	global Supervisor::status_request: event(id: count, nodes: string);
	global Supervisor::status_response: event(id: count, result: Status);

	global Supervisor::create_request: event(id: count, node: Node);
	global Supervisor::create_response: event(id: count, result: string);

	global Supervisor::destroy_request: event(id: count, nodes: string);
	global Supervisor::destroy_response: event(id: count, result: bool);

	global Supervisor::restart_request: event(id: count, nodes: string);
	global Supervisor::restart_response: event(id: count, result: bool);
}
