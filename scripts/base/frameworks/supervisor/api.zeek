##! The Zeek process supervision API.
##! This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
##! That is, it may change in various incompatible ways without warning or
##! deprecation until the stable 4.0.0 release.

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
		## The PCAP file name from which the node will read/analyze packets.
		## Typically used by worker nodes.
		pcap_file: string &optional;
	};

	## Configuration options that influence behavior of a supervised Zeek node.
	type NodeConfig: record {
		## The name of the supervised node.  These are unique within a given
		## supervised process tree and typically human-readable.
		name: string;
		## The interface name from which the node will read/analyze packets.
		interface: string &optional;
		## The PCAP file name from which the node will read/analyze packets.
		pcap_file: string &optional;
		## The working directory that the node should use.
		directory: string &optional;
		## The filename/path to which the node's stdout will be redirected.
		stdout_file: string &optional;
		## The filename/path to which the node's stderr will be redirected.
		stderr_file: string &optional;
		## Whether to start the node in bare mode. When left out, the node
		## inherits the bare-mode status the supervisor itself runs with.
		bare_mode: bool &optional;
		## Additional script filenames/paths that the node should load
		## after the base scripts, and prior to any user-specified ones.
		addl_base_scripts: vector of string &default = vector();
		## Additional script filenames/paths that the node should load
		## after any user-specified scripts.
		addl_user_scripts: vector of string &default = vector();
		## The former name of addl_user_scripts.
		scripts: vector of string &default = vector()
		    &deprecated="Remove in 6.1. Use the addl_user_scripts field instead.";
		## Environment variables to define in the supervised node.
		env: table[string] of string &default=table();
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

	## Hooks into the stdout stream for all supervisor's child processes.
	## If a hook terminates with `break`, that will suppress output to the
	## associated stream.
	##
	## node: the name of a previously created node via
	##       :zeek:see:`Supervisor::create` indicating to which
	##       child process the stdout line is associated.
	##       An empty value is used to indicate the message
	##       came from the internal supervisor stem process
	##       (this should typically never happen).
	##
	## msg: line-buffered contents from the stdout of a child process.
	global stdout_hook: hook(node: string, msg: string);

	## Hooks into the stderr stream for all supervisor's child processes.
	## If a hook terminates with `break`, that will suppress output to the
	## associated stream.
	##
	## node: the name of a previously created node via
	##       :zeek:see:`Supervisor::create` indicating to which
	##       child process the stdout line is associated.
	##       A empty value is used to indicate the message
	##       came from the internal supervisor stem process.
	##       (this should typically never happen).
	##
	## msg: line-buffered contents from the stderr of a child process.
	global stderr_hook: hook(node: string, msg: string);

	## A notification event the Supervisor generates when it receives a
	## status message update from the stem, indicating node has
	## (re-)started.
	##
	## node: the name of a previously created node via
	##       :zeek:see:`Supervisor::create` indicating to which
	##       child process the stdout line is associated.
	##
	## pid: the process ID the stem reported for this node.
	global node_status: event(node: string, pid: count);
}
