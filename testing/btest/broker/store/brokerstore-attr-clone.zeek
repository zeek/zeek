# Start master and two clones. One clone changes table and the change ends up in master + other clone.

# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run master "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run cloneone "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../cloneone.zeek >../cloneone.out"
# @TEST-EXEC: btest-bg-run clonetwo "zeek -b %DIR/sort-stuff.zeek ../common.zeek ../clonetwo.zeek >../clonetwo.out"
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: btest-diff master.out
# @TEST-EXEC: btest-diff clonetwo.out

@TEST-START-FILE common.zeek
redef exit_only_after_terminate = T;

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

event dump_tables()
	{
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

event do_terminate()
	{ terminate(); }
@TEST-END-FILE

@TEST-START-FILE master.zeek

event zeek_init()
	{
	Broker::subscribe("master");
	tablestore = Broker::create_master("table");
	setstore = Broker::create_master("set");
	recordstore = Broker::create_master("rec");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

global peers = 0;

event check_all_set()
	{
	if ( "whatever" in t && "hi" in s && "b" in r )
		{
		event dump_tables();
		Broker::publish("cloneone", do_terminate);
		Broker::publish("clonetwo", check_all_set);
		}
	else
		schedule 0.1sec { check_all_set() };
	}

global send_stuff_over: event();

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers;
	print "Peer added ";

	if ( peers == 2 )
		{
		Broker::publish("cloneone", send_stuff_over);
		schedule 0.1sec { check_all_set() };
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	--peers;

	if ( peers == 0 )
		terminate();
	}
@TEST-END-FILE

@TEST-START-FILE cloneone.zeek
event zeek_init()
	{
	Broker::subscribe("cloneone");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event send_stuff_over()
	{
	print "Inserting stuff";
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

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added", endpoint;
	tablestore = Broker::create_clone("table");
	setstore = Broker::create_clone("set");
	recordstore = Broker::create_clone("rec");
	}
@TEST-END-FILE

@TEST-START-FILE clonetwo.zeek
event zeek_init()
	{
	Broker::subscribe("clonetwo");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event check_all_set()
	{
	if ( "whatever" in t && "hi" in s && "b" in r )
		{
		event dump_tables();
		terminate();
		}
	else
		schedule 0.1sec { check_all_set() };
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added";
	tablestore = Broker::create_clone("table");
	setstore = Broker::create_clone("set");
	recordstore = Broker::create_clone("rec");
	}
@TEST-END-FILE
