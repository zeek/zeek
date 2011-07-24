@load utils/numbers

@load frameworks/notice
@load frameworks/control

module Cluster;

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
	
	## Events sent by the control host (i.e. BroControl) when dynamically 
	## connecting to a running instance to update settings or request data.
	const control_events = Control::controller_events &redef;
	
	## Record type to indicate a node in a cluster.
	type Node: record {
		node_type:    NodeType;
		ip:           addr;
		p:            port;
		
		## Identifier for the interface a worker is sniffing.
		interface:    string      &optional;
		
		## Manager node this node uses.  For workers and proxies.
		manager:      string      &optional;
		## Proxy node this node uses.  For workers and managers.
		proxy:        string      &optional;
		## Worker nodes that this node connects with.  For managers and proxies.
		workers:      set[string] &optional;
		time_machine: string      &optional;
	};
	
	const nodes: table[string] of Node = {} &redef;
	
	## This is usually supplied on the command line for each instance
	## of the cluster that is started up.
	const node = getenv("CLUSTER_NODE") &redef;
}

event bro_init()
	{
	if ( node != "" && node !in nodes )
		{
		local msg = "You didn't supply a valid node in the Cluster::nodes configuration.";
		event reporter_error(current_time(), msg, "");
		terminate();
		}
	
	Log::create_stream(CLUSTER, [$columns=Info]);
	}