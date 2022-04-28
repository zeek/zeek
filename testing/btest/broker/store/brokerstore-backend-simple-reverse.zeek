# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: btest-bg-run manager-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clone2.zeek >../clone2.out"
# @TEST-EXEC: btest-bg-wait 40
#
# @TEST-EXEC: btest-diff master.out
# @TEST-EXEC: btest-diff clone.out
# @TEST-EXEC: diff master.out clone.out
# @TEST-EXEC: diff master.out clone2.out

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

@TEST-START-FILE common.zeek
@load base/frameworks/cluster

redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0secs;

type testrec: record {
	a: count;
	b: string;
	c: vector of string;
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;
global rt: table[string, testrec] of count &backend=Broker::MEMORY;

event go_away()
	{
	terminate();
	}

function all_stores_set(): bool
	{
	return "whatever" in t && "hi" in s && "b" in r;
	}
@TEST-END-FILE

@TEST-START-FILE master.zeek

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=1
	{
	Reporter::info(fmt("Peer added: %s", cat(endpoint)));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	Reporter::info(fmt("Peer lost: %s", cat(endpoint)));
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	print rt;
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek

global has_node_up: bool = F;
global has_announce_masters: bool = F;

event dump_tables()
	{
	t["a"] = 5;
	delete t["a"];
	add s["hi"];
	t["a"] = 2;
	t["a"] = 3;
	t["b"] = 3;
	t["c"] = 4;
	delete t["c"];
	t["whatever"] = 5;
	r["a"] = testrec($a=1, $b="b", $c=vector("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=vector("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=vector("elem1", "elem2"));
	rt["a", testrec($a=1, $b="b", $c=vector("elem1", "elem2"))] = 1;
	rt["a", testrec($a=1, $b="b", $c=vector("elem1", "elem2"))] += 1;
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	print rt;
	}

event Cluster::node_up(name: string, id: string)
	{
	Reporter::info(fmt("Node Up: %s", name));
	has_node_up = T;
	if ( has_announce_masters )
		event dump_tables();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event Broker::announce_masters(masters: set[string])
	{
	Reporter::info(fmt("Received announce_masters: %s", cat(masters)));
	has_announce_masters = T;
	if ( has_node_up )
		event dump_tables();
	}
@TEST-END-FILE

@TEST-START-FILE clone2.zeek
event dump_tables()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	print rt;
	terminate();
	}

event Broker::announce_masters(masters: set[string])
	{
	Reporter::info(fmt("Received announce_masters: %s", cat(masters)));
	}

event check_all_set()
	{
	if ( all_stores_set() )
		event dump_tables();
	else
		schedule 0.1sec { check_all_set() };
	}

event Cluster::node_up(name: string, id: string)
	{
	Reporter::info(fmt("Node Up: %s", name));
	schedule 0.1sec { check_all_set() };
	}
@TEST-END-FILE

