# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: zeek -B broker -b one.zeek > output1
# @TEST-EXEC: btest-bg-run master "cp ../*.sqlite . && zeek -B broker -b ../two.zeek >../output2"
# @TEST-EXEC: btest-bg-run clone "zeek -B broker -b ../three.zeek >../output3"
# @TEST-EXEC: btest-bg-wait 15

# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff output2
# @TEST-EXEC: btest-diff output3

# the first test writes out the sqlite files...

@TEST-START-FILE one.zeek

module TestModule;

global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &broker_store="table";
global s: set[string] &broker_store="set";
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec";

event zeek_init()
	{
	tablestore = Broker::create_master("table", Broker::SQLITE);
	setstore = Broker::create_master("set", Broker::SQLITE);
	recordstore = Broker::create_master("rec", Broker::SQLITE);
	t["a"] = 5;
	t["b"] = 3;
	t["c"] = 4;
	t["whatever"] = 5;
	delete t["c"];
	add s["I am a set!"];
	add s["I am really a set!"];
	add s["Believe me - I am a set"];
	r["a"] = testrec($a=1, $b="b", $c=set("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=set("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=set("elem1", "elem2"));
	print t;
	print s;
	print r;
	}

@TEST-END-FILE
@TEST-START-FILE two.zeek

# read in again - and serve to clones

redef exit_only_after_terminate = T;

module TestModule;

global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &broker_store="table";
global s: set[string] &broker_store="set";
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec";

event zeek_init()
	{
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	tablestore = Broker::create_master("table", Broker::SQLITE);
	setstore = Broker::create_master("set", Broker::SQLITE);
	recordstore = Broker::create_master("rec", Broker::SQLITE);
	print t;
	print s;
	print r;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE three.zeek

# get copy from master

redef exit_only_after_terminate = T;

module TestModule;

global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};


global t: table[string] of count &broker_store="table";
global s: set[string] &broker_store="set";
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec";

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event print_me()
	{
	print t;
	print s;
	print r;
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	tablestore = Broker::create_clone("table");
	setstore = Broker::create_clone("set");
	recordstore = Broker::create_clone("rec");
	schedule 2sec { print_me() };
	}


@TEST-END-FILE
