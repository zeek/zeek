# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: btest-bg-run manager-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -B broker ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -B broker ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -B broker ../clone2.zeek >../clone2.out"
# @TEST-EXEC: btest-bg-wait 40
#
# @TEST-EXEC: btest-diff master.out
# @TEST-EXEC: btest-diff clone.out

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE


@TEST-START-FILE master.zeek
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

global terminate_count = 0;

event zeek_init()
	{
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=1
	{
	Reporter::info(fmt("Peer added: %s", cat(endpoint)));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	Reporter::info(fmt("Peer lost: %s", cat(endpoint)));
	terminate_count += 1;
	if ( terminate_count == 2)
		{
		terminate();
		print t;
		print s;
		print r;
		}
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

event terminate_me()
	{
	terminate();
	}

event dump_tables()
	{
	t["a"] = 5;
	delete t["a"];
	add s["hi"];
	t["a"] = 2;
	t["a"] = 3;
	t["b"] = 3;
	t["c"] = 4;
	t["whatever"] = 5;
	delete t["c"];
	r["a"] = testrec($a=1, $b="b", $c=set("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=set("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=set("elem1", "elem2"));
	print t;
	print s;
	print r;
	schedule 10sec { terminate_me() };
	}

event Cluster::node_up(name: string, id: string)
	{
	Reporter::info(fmt("Node Up: %s", name));
	schedule 5secs { dump_tables() };
	}

event Broker::announce_masters(masters: set[string])
	{
	Reporter::info(fmt("Received announce_masters: %s", cat(masters)));
	}

@TEST-END-FILE

@TEST-START-FILE clone2.zeek
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

event dump_tables()
	{
	print t;
	print s;
	print r;
	terminate();
	}

event Broker::announce_masters(masters: set[string])
	{
	Reporter::info(fmt("Received announce_masters: %s", cat(masters)));
	}

event Cluster::node_up(name: string, id: string)
	{
	Reporter::info(fmt("Node Up: %s", name));
	schedule 20secs { dump_tables() };
	}
@TEST-END-FILE

