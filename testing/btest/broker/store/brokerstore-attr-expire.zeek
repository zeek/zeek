# So - this test currently is not really that great. The goal was to test expiration after
# syncing values with Broker. However, it turns out that the delays introduced by Broker seem
# a bit random - and too high to really test this without the test taking forever.
#
# so - instead we just check that expiries do indeed happen - however the ordering is not as
# guaranteed as I would have liked to have it.


# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run master "zeek -b ../common.zeek ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run clone "zeek -b ../common.zeek ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff clone.out

@TEST-START-FILE common.zeek
redef exit_only_after_terminate = T;
redef table_expire_interval = 0.5sec;

global tablestore: opaque of Broker::Store;
global setstore: opaque of Broker::Store;
global recordstore: opaque of Broker::Store;

type testrec: record {
	a: count;
	b: string;
	c: vector of string;
};

function change_t(tbl: any, tpe: TableChange, idx: string, idxb: count)
	{
	if ( tpe == TABLE_ELEMENT_EXPIRED )
		print fmt("Expiring t: %s", idx);
	}

function change_s(tbl: any, tpe: TableChange, idx: string, idbx: count)
	{
	if ( tpe == TABLE_ELEMENT_EXPIRED )
		print fmt("Expiring s: %s", idx);
	}

function change_r(tbl: any, tpe: TableChange, idx: string, idxb: testrec)
	{
	if ( tpe == TABLE_ELEMENT_EXPIRED )
		print fmt("Expiring r: %s", idx);
	}

global t: table[string] of count &broker_store="table" &create_expire=4sec &on_change=change_t;
global s: table[string] of count &broker_store="set" &write_expire=3sec &on_change=change_s;
global r: table[string] of testrec &broker_allow_complex_type &broker_store="rec" &write_expire=5sec &on_change=change_r;
@TEST-END-FILE

@TEST-START-FILE master.zeek
event zeek_init()
	{
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	tablestore = Broker::create_master("table");
	setstore = Broker::create_master("set");
	recordstore = Broker::create_master("rec");
	}

event update_stuff()
	{
	t["a"] = 3;
	t["expire_later_in_t_not_with_a"] = 4;
	s["expire_later"] = 2;
	r["reca"] = testrec($a=1, $b="c", $c=vector("elem1", "elem2"));
	}

event insert_stuff()
	{
	print "Inserting stuff";
	t["a"] = 5;
	delete t["a"];
	s["expire_first"] = 0;
	s["expire_later"] = 1;
	t["a"] = 2;
	t["b"] = 3;
	t["whatever"] = 5;
	r["reca"] = testrec($a=1, $b="b", $c=vector("elem1", "elem2"));
	r["recb"] = testrec($a=2, $b="d", $c=vector("elem1", "elem2"));
	print t;
	print s;
	print r;
	schedule 1.5sec { update_stuff() };
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added ", endpoint;
	event insert_stuff();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Terminating";
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
	print t;
	print s;
	print r;
	print "terminating";
	terminate();
	}

event check_all_unset()
	{
	if ( |t| == 0 && |s| == 0 && |r| == 0 )
		event dump_tables();
	else
		schedule 0.1sec { check_all_unset() };
	}

event check_all_set()
	{
	if ( "whatever" in t && "expire_later" in s && "recb" in r )
		schedule 0.1sec { check_all_unset() };
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
