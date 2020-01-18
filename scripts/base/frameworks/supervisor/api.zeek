##! The Zeek process supervision API.

module Supervisor;

export {
	## The role a supervised-node will play in Zeek's Cluster Framework.
	type ClusterRole: enum {
		NONE,
		LOGGER,
		MANAGER,
		PROXY,
		WORKER,
	};

	## Describes configuration of a supervised-node within Zeek's Cluster
	## Framework.
	type ClusterEndpoint: record {
		## The role a supervised-node will play in Zeek's Cluster Framework.
		role: ClusterRole;
		## The host/IP at which the cluster node runs.
		host: addr;
		## The TCP port at which the cluster node listens for connections.
		p: port;
		## The interface name from which the node will read/analyze packets.
		## Typically used by worker nodes.
		interface: string &optional;
	};

	## Configuration options that influence behavior of a supervised Zeek node.
	type NodeConfig: record {
		## The name of the supervised node.  These are unique within a given
		## supervised process tree and typically human-readable.
		name: string;
		## The interface name from which the node will read/analyze packets.
		interface: string &optional;
		## The working directory that the node should use.
		directory: string &optional;
		## The filename/path to which the node's stdout will be redirected.
		stdout_file: string &optional;
		## The filename/path to which the node's stderr will be redirected.
		stderr_file: string &optional;
		## Additional script filenames/paths that the node should load.
		scripts: vector of string &default = vector();
		## A cpu/core number to which the node will try to pin itself.
		cpu_affinity: int &optional;
		## The Cluster Layout definition.  Each node in the Cluster Framework
		## knows about the full, static cluster topology to which it belongs.
		## Entries use node names for keys.  The Supervisor framework will
		## automatically translate this table into the right Cluster Framework
		## configuration when spawning supervised-nodes.  E.g. it will
		## populate the both the CLUSTER_NODE environment variable and
		## :zeek:see:`Cluster::nodes` table.
		cluster: table[string] of ClusterEndpoint &default=table();
	};

	## The current status of a supervised node.
	type NodeStatus: record {
		## The desired node configuration.
		node: NodeConfig;
		## The current or last known process ID of the node.  This may not
		## be initialized if the process has not yet started.
		pid: int &optional;
	};

	## The current status of a set of supervised nodes.
	type Status: record {
		## The status of supervised nodes, keyed by node names.
		nodes: table[string] of NodeStatus;
	};

	## Create a new supervised node process.
	## It's an error to call this from a process other than a Supervisor.
	##
	## node: the desired configuration for the new supervised node process.
	##
	## Returns: an empty string on success or description of the error/failure.
	global create: function(node: NodeConfig): string;

	## Retrieve current status of a supervised node process.
	## It's an error to call this from a process other than a Supervisor.
	##
	## node: the name of the node to get the status of or an empty string
	##       to mean "all nodes".
	##
	## Returns: the current status of a set of nodes.
	global status: function(node: string &default=""): Status;

	## Restart a supervised node process by destroying (killing) and
	## re-recreating it.
	## It's an error to call this from a process other than a Supervisor.
	##
	## node: the name of the node to restart or an empty string to mean
	##       "all nodes".
	##
	## Returns: true on success.
	global restart: function(node: string &default=""): bool;

	## Destroy and remove a supervised node process.
	## It's an error to call this from a process other than a Supervisor.
	##
	## node: the name of the node to destroy or an empty string to mean
	##       "all nodes".
	##
	## Returns: true on success.
	global destroy: function(node: string &default=""): bool;

	## Returns: true if this is the Supervisor process.
	global is_supervisor: function(): bool;

	## Returns: true if this is a supervised node process.
	global is_supervised: function(): bool;

	## Returns: the node configuration if this is a supervised node.
	##          It's an error to call this function from a process other than
	##          a supervised one.
	global node: function(): NodeConfig;

	## Send a request to a remote Supervisor process to create a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the desired configuration for the new supervised node process.
	global Supervisor::create_request: event(reqid: string, node: NodeConfig);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`Supervisor::create_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::create`.
	global Supervisor::create_response: event(reqid: string, result: string);

	## Send a request to a remote Supervisor process to retrieve node status.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to get status of or empty string to mean "all
	##       nodes".
	global Supervisor::status_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`Supervisor::status_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::status`.
	global Supervisor::status_response: event(reqid: string, result: Status);

	## Send a request to a remote Supervisor process to restart a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to restart or empty string to mean "all
	##       nodes".
	global Supervisor::restart_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`Supervisor::restart_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::restart`.
	global Supervisor::restart_response: event(reqid: string, result: bool);

	## Send a request to a remote Supervisor process to destroy a node.
	##
	## reqid: an arbitrary string that will be directly echoed in the response
	##
	## node: the name of the node to destory or empty string to mean "all
	##       nodes".
	global Supervisor::destroy_request: event(reqid: string, node: string);

	## Handle a response from a Supervisor process that received
	## :zeek:see:`Supervisor::destroy_request`.
	##
	## reqid: an arbitrary string matching the value in the original request.
	##
	## result: the return value of the remote call to
	##         :zeek:see:`Supervisor::destroy`.
	global Supervisor::destroy_response: event(reqid: string, result: bool);

	## Send a request to a remote Supervisor to stop and shutdown its
	## process tree.  There is no response to this message as the Supervisor
	## simply terminates on receipt.
	global Supervisor::stop_request: event();
}
