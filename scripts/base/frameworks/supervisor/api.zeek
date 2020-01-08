##! The Zeek process supervision API.
# TODO: add proper docs

module Supervisor;

export {
	type ClusterRole: enum {
		NONE,
		LOGGER,
		MANAGER,
		PROXY,
		WORKER,
	};

	type ClusterEndpoint: record {
		role: ClusterRole;
		host: addr;
		p: port;
		interface: string &optional;
	};

	type Node: record {
		name: string;
		interface: string &optional;
		directory: string &optional;
		scripts: vector of string &default = vector();
		cluster: table[string] of ClusterEndpoint &default=table();

		# TODO: separate node config fields from status fields ?
		# TODO: add more status fields ?
		pid: count &optional;
	};

	type Status: record {
		nodes: table[string] of Node;
	};

	global status: function(nodes: string &default="all"): Status;
	global create: function(node: Node): string;
	global destroy: function(nodes: string): bool;
	global restart: function(nodes: string &default="all"): bool;

	global is_supervisor: function(): bool;
	global is_supervised: function(): bool;

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
