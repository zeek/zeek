# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: btest-bg-run manager-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b -B broker ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b -B broker ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b -B broker ../clone.zeek >../clone2.out"
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: grep -v PEER_UNAVAILABLE worker-1/.stderr > worker-1-stderr
# @TEST-EXEC: btest-diff worker-1-stderr

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE


@TEST-START-FILE master.zeek
@load base/frameworks/cluster
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

module TestModule;

global t: table[string] of count &backend=Broker::MEMORY;
global s: table[string] of string &backend=Broker::MEMORY;

event zeek_init()
	{
	t["a"] = 5;
	s["a"] = "b";
	print t;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek
@load base/frameworks/cluster
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

module TestModule;

global t: table[count] of count &backend=Broker::MEMORY;
global s: table[string] of count &backend=Broker::MEMORY;

event dump_tables()
	{
	print t;
	print s;
	terminate();
	}

event Cluster::node_up(name: string, id: string)
	{
	#print "node up", name;
	schedule 4secs { dump_tables() };
	}
@TEST-END-FILE
