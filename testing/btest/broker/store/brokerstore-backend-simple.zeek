# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: btest-bg-run manager-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clone.zeek >../clone2.out"
# @TEST-EXEC: btest-bg-wait 30
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
@load base/frameworks/broker

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

@TEST-END-FILE

@TEST-START-FILE master.zeek
event zeek_init()
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
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

global peers_lost = 0;
event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers_lost;

	if ( peers_lost == 2 )
		terminate();
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek

event dump_tables()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	terminate();
	}

event check_all_set()
	{
	if ( "whatever" in t && "hi" in s && "b" in r )
		event dump_tables();
	else
		schedule 0.1sec { check_all_set() };
	}


event Cluster::node_up(name: string, id: string)
	{
	schedule 0.1sec { check_all_set() };
	}
@TEST-END-FILE
