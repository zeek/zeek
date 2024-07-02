##! This module holds the basic types needed for the Management framework. These
##! are used by both cluster agent and controller, and several have corresponding
##! implementations in zeek-client.

module Management;

export {
	## Management infrastructure node type. This intentionally does not
	## include the managed cluster node types (worker, logger, etc) -- those
	## continue to be managed by the cluster framework.
	type Role: enum {
		NONE,       ##< No active role in cluster management
		AGENT,      ##< A cluster management agent.
		CONTROLLER, ##< The cluster's controller.
		NODE,       ##< A managed cluster node (worker, manager, etc).
	};

	## A Zeek-side option with value.
	type Option: record {
		name: string;  ##< Name of option
		value: string; ##< Value of option
	};

	## Configuration describing a Zeek instance running a Cluster
	## Agent. Normally, there'll be one instance per cluster
	## system: a single physical system.
	type Instance: record {
		## Unique, human-readable instance name
		name: string;
		## IP address of system
		host: addr;
		## Agent listening port. Not needed if agents connect to controller.
		listen_port: port &optional;
	};

	type InstanceVec: vector of Instance;

	## State that a Cluster Node can be in. State changes trigger an
	## API notification (see notify_change()). The Pending state corresponds
	## to the Supervisor not yet reporting a PID for a node when it has not
	## yet fully launched.
	type State: enum {
		PENDING,  ##< Not yet running
		RUNNING,  ##< Running and operating normally
		STOPPED,  ##< Explicitly stopped
		FAILED,   ##< Failed to start; and permanently halted
		CRASHED,  ##< Crashed, will be restarted,
		UNKNOWN,  ##< State not known currently (e.g., because of lost connectivity)
	};

	## Configuration describing a Cluster Node process.
	type Node: record {
		name: string;                        ##< Cluster-unique, human-readable node name
		instance: string;                    ##< Name of instance where node is to run
		role: Supervisor::ClusterRole;       ##< Role of the node.
		state: State;                        ##< Desired, or current, run state.
		p: port &optional;                   ##< Port on which this node will listen
		scripts: vector of string &optional; ##< Additional Zeek scripts for node
		options: set[Option] &optional;      ##< Zeek options for node
		interface: string &optional;         ##< Interface to sniff
		cpu_affinity: int &optional;         ##< CPU/core number to pin to
		env: table[string] of string &default=table(); ##< Custom environment vars
		metrics_port: port &optional;        ##< Metrics exposure port, for Prometheus
	};

	## Data structure capturing a cluster's complete configuration.
	type Configuration: record {
		id: string &default=unique_id(""); ##< Unique identifier for a particular configuration
		## The instances in the cluster.
		instances: set[Instance] &default=set();

		## The set of nodes in the cluster, as distributed over the instances.
		nodes: set[Node] &default=set();
	};

	## The status of a Supervisor-managed node, as reported to the client in
	## a get_nodes_request/get_nodes_response transaction.
	type NodeStatus: record {
		## Cluster-unique, human-readable node name
		node: string;
		## Current run state of the node.
		state: State;
		## Role the node plays in cluster management.
		mgmt_role: Role &default=NONE;
		## Role the node plays in the Zeek cluster.
		cluster_role: Supervisor::ClusterRole &default=Supervisor::NONE;
		## Process ID of the node. This is optional because the Supervisor may not have
		## a PID when a node is still bootstrapping.
		pid: int &optional;
		## The node's Broker peering listening port, if any.
		p: port &optional;
		## The node's metrics port for Prometheus, if any.
		metrics_port: port &optional;
	};

	type NodeStatusVec: vector of NodeStatus;

	## Return value for request-response API event pairs. Some responses
	## contain one, others multiple of these. The request ID allows clients
	## to string requests and responses together. Agents and the controller
	## fill in the instance and node fields whenever there's sufficient
	## context to define them. Any result produced by an agent will carry an
	## instance value, for example.
	type Result: record {
		reqid: string;                ##< Request ID of operation this result refers to
		success: bool &default=T;     ##< True if successful
		instance: string &optional;   ##< Name of associated instance (for context)
		data: any &optional;          ##< Addl data returned for successful operation
		error: string &optional;      ##< Descriptive error on failure
		node: string &optional;       ##< Name of associated node (for context)
	};

	type ResultVec: vector of Result;

	## In :zeek:see:`Management::Controller::API::deploy_response` events,
	## each :zeek:see:`Management::Result` indicates the outcome of a
	## launched cluster node. If a node does not launch properly (meaning
	## it doesn't check in with the agent on the machine it's running on),
	## the result will indicate failure, and its data field will be an
	## instance of this record, capturing the stdout and stderr output of
	## the failing node.
	type NodeOutputs: record {
		stdout: string; ##< The stdout stream of a Zeek process
		stderr: string; ##< The stderr stream of a Zeek process
	};

	## Given a :zeek:see:`Management::Result` record,
	## this function returns a string summarizing it.
	global result_to_string: function(res: Result): string;

	## Given a vector of :zeek:see:`Management::Result` records,
	## this function returns a string summarizing them.
	global result_vec_to_string: function(res: ResultVec): string;
}

function result_to_string(res: Result): string
	{
	local result = "";

	if ( res$success )
		result = "success";
	else if ( res?$error )
		result = fmt("error (%s)", res$error);
	else
		result = "error";

	local details: string_vec;

	if ( res$reqid != "" )
		details[|details|] = fmt("reqid %s", res$reqid);
	if ( res?$instance )
		details[|details|] = fmt("instance %s", res$instance);
	if ( res?$node && res$node != "" )
		details[|details|] = fmt("node %s", res$node);

	if ( |details| > 0 )
		result = fmt("%s (%s)", result, join_string_vec(details, ", "));

	return result;
	}

function result_vec_to_string(res: ResultVec): string
	{
	local ret: vector of string;

	for ( idx in res )
		ret += result_to_string(res[idx]);;

	return join_string_vec(ret, ", ");
	}
