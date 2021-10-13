# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run master "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run clone "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: btest-diff clone.out

@TEST-START-FILE common.zeek
redef exit_only_after_terminate = T;

global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &broker_store="table";
global s: set[string, string] &broker_store="set";
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec";
@TEST-END-FILE

@TEST-START-FILE master.zeek
event zeek_init()
	{
	tablestore = Broker::create_master("table");
	setstore = Broker::create_master("set");
	recordstore = Broker::create_master("rec");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event insert_stuff()
	{
	print "Inserting stuff";
	t["a"] = 5;
	delete t["a"];
	add s["hi", "there"];
	t["a"] = 2;
	t["a"] = 3;
	t["b"] = 3;
	t["c"] = 4;
	delete t["c"];
	t["whatever"] = 5;
	r["a"] = testrec($a=1, $b="b", $c=set("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=set("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=set("elem1", "elem2"));
	print sort_table(t);
	print s;
	print sort_table(r);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added ", endpoint;
	event insert_stuff();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek
event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event dump_tables()
	{
	print sort_table(t);
	print s;
	print sort_table(r);
	terminate();
	}

event check_all_set()
	{
	if ( "whatever" in t && ["hi", "there"] in s && "b" in r )
		event dump_tables();
	else
		schedule 0.1sec { check_all_set() };
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added";
	tablestore = Broker::create_clone("table");
	setstore = Broker::create_clone("set");
	recordstore = Broker::create_clone("rec");
	schedule 0.1sec { check_all_set() };
	}
@TEST-END-FILE
