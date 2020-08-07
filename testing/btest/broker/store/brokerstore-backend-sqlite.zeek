# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: zeek %DIR/sort-stuff.zeek preseed-sqlite.zeek;
# @TEST-EXEC: btest-bg-run manager-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -B broker %DIR/sort-stuff.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -B broker %DIR/sort-stuff.zeek ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -B broker %DIR/sort-stuff.zeek ../clone.zeek >../clone2.out"
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

@TEST-START-FILE preseed-sqlite.zeek

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::SQLITE;
global s: set[string] &backend=Broker::SQLITE;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::SQLITE;

event zeek_init()
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
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

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

function change_function(t: table[string] of count, tpe: TableChange, idxa: string, val: count)
	{
	print "This should not print";
	print "change_function", idxa, val, tpe;
	}

global t: table[string] of count &backend=Broker::SQLITE &on_change=change_function;
global s: set[string] &backend=Broker::SQLITE;
global r: table[string] of testrec &broker_allow_complex_type &backend=Broker::SQLITE;

redef Broker::table_store_db_directory = "..";

event zeek_init()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
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


event dump_tables()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	terminate();
	}

event Cluster::node_up(name: string, id: string)
	{
	#print "node up", name;
	schedule 15secs { dump_tables() };
	}
@TEST-END-FILE
