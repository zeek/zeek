@load utils/numbers

module Cluster;

const ENV_VAR = getenv("CLUSTER_NODE");
const ENVIRONMENT_NODE = (ENV_VAR == "" ? 0: extract_count(ENV_VAR));

# Only load the communication framework if it really looks like someone is
# trying to start up a cluster node.
@if ( ENVIRONMENT_NODE != 0 )
@load frameworks/communication
@endif

export {
	redef enum Log::ID += { CLUSTER };
	type Info: record {
		ts:       time;
		message:  string;
	} &log;
	
	type NodeType: enum {
		CONTROL,
		MANAGER,
		PROXY,
		WORKER,
		TIME_MACHINE,
	};
	
	## Events raised by the manager and handled by the workers.
	const manager_events = /Drop::.*/ &redef;
	
	## Events raised by the proxies and handled by the manager.
	const proxy_events = /Notice::notice/ &redef;
	
	## Events raised by workers and handled by the manager.
	const worker_events = /(Notice::notice|TimeMachine::command|Drop::.*)/ &redef;
	
	## Events sent by the manager host (i.e. BroControl) when dynamically 
	## connecting to a running instance to update settings or request data.
	const control_events = /Cluster::(configuration_update|request_id|get_peer_status)/ &redef;
	
	## Directory where the cluster is archiving logs.
	## TODO: we need a sane default here.
	const log_dir = "/not/set" &redef;
		
	## Record type to indicate a node in a cluster.
	type Node: record {
		node_type:    NodeType;
		ip:           addr;
		p:            port;
		tag:          string;
		
		## Identifier for the interface a worker is sniffing.
		interface:    string     &optional;
		
		## Manager node this node uses.  For workers and proxies.
		manager:      count      &optional;
		## Proxy node this node uses.  For workers and managers.
		proxy:        count      &optional;
		## Worker nodes that this node connects with.  For managers and proxies.
		workers:      set[count] &optional;
		time_machine: count      &optional;
	};
	
	const nodes: table[count] of Node = {} &redef;
	
	## This will frequently be supplied on the command line for each instance
	## of the cluster that is started up.
	const node = ENVIRONMENT_NODE &redef;
}

event bro_init() &priority=10
	{
	if ( 0 in nodes )
		{
		local msg = "You can't supply a node at the zero value in the Cluster::nodes configuration.";
		event reporter_error(current_time(), msg, "");
		terminate();
		}
	}

event bro_init()
	{
	Log::create_stream(CLUSTER, [$columns=Info]);
	}