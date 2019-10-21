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

	global Supervisor::status_request: event(reqid: string, nodes: string);
	global Supervisor::status_response: event(reqid: string, result: Status);

	global Supervisor::create_request: event(reqid: string, node: Node);
	global Supervisor::create_response: event(reqid: string, result: string);

	global Supervisor::destroy_request: event(reqid: string, nodes: string);
	global Supervisor::destroy_response: event(reqid: string, result: bool);

	global Supervisor::restart_request: event(reqid: string, nodes: string);
	global Supervisor::restart_response: event(reqid: string, result: bool);
}
