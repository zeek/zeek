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

	type NodeConfig: record {
		name: string;
		interface: string &optional;
		directory: string &optional;
		stdout_file: string &optional;
		stderr_file: string &optional;
		scripts: vector of string &default = vector();
		cpu_affinity: int &optional;
		cluster: table[string] of ClusterEndpoint &default=table();
	};

	type NodeStatus: record {
		node: NodeConfig;
		pid: int &optional;
	};

	type Status: record {
		nodes: table[string] of NodeStatus;
	};

	global create: function(node: NodeConfig): string;
	global status: function(node: string &default=""): Status;
	global restart: function(node: string &default=""): bool;
	global destroy: function(node: string &default=""): bool;

	global is_supervisor: function(): bool;
	global is_supervised: function(): bool;

	global Supervisor::create_request: event(reqid: string, node: NodeConfig);
	global Supervisor::create_response: event(reqid: string, result: string);

	global Supervisor::status_request: event(reqid: string, node: string);
	global Supervisor::status_response: event(reqid: string, result: Status);

	global Supervisor::restart_request: event(reqid: string, node: string);
	global Supervisor::restart_response: event(reqid: string, result: bool);

	global Supervisor::destroy_request: event(reqid: string, node: string);
	global Supervisor::destroy_response: event(reqid: string, result: bool);

	global Supervisor::stop_request: event();
}
