# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: zeek -b %DIR/sort-stuff.zeek common.zeek one.zeek > output1
# @TEST-EXEC: btest-bg-run master "cp ../*.sqlite . && zeek -b %DIR/sort-stuff.zeek ../common.zeek ../two.zeek >../output2"
# @TEST-EXEC: btest-bg-run clone "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../three.zeek >../output3"
# @TEST-EXEC: btest-bg-wait 20

# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff output2
# @TEST-EXEC: btest-diff output3
# @TEST-EXEC: diff output1 output2
# @TEST-EXEC: diff output2 output3

@TEST-START-FILE common.zeek
global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: vector of string;
};

global t: table[string] of count &broker_store="table";
global s: set[string] &broker_store="set";
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec";
@TEST-END-FILE

# the first test writes out the sqlite files...

@TEST-START-FILE one.zeek
redef exit_only_after_terminate = T;

event zeek_init()
	{
	tablestore = Broker::create_master("table", Broker::SQLITE);
	setstore = Broker::create_master("set", Broker::SQLITE);
	recordstore = Broker::create_master("rec", Broker::SQLITE);
	t["a"] = 5;
	t["b"] = 3;
	t["c"] = 4;
	delete t["c"];
	t["whatever"] = 5;
	add s["I am a set!"];
	add s["I am really a set!"];
	add s["Believe me - I am a set"];
	r["a"] = testrec($a=1, $b="b", $c=vector("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=vector("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=vector("elem1", "elem2"));
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	terminate();
	}

@TEST-END-FILE
@TEST-START-FILE two.zeek
redef exit_only_after_terminate = T;

# read in again - and serve to clones

event zeek_init()
	{
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	tablestore = Broker::create_master("table", Broker::SQLITE);
	setstore = Broker::create_master("set", Broker::SQLITE);
	recordstore = Broker::create_master("rec", Broker::SQLITE);
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE three.zeek
redef exit_only_after_terminate = T;

# get copy from master

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event print_me()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	terminate();
	}

event check_all_set()
	{
	if ( "whatever" in t && |s| == 3 && "b" in r )
		event print_me();
	else
		schedule 0.1sec { check_all_set() };
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	tablestore = Broker::create_clone("table");
	setstore = Broker::create_clone("set");
	recordstore = Broker::create_clone("rec");
	schedule 0.1sec { check_all_set() };
	}


@TEST-END-FILE
