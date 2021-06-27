# @TEST-EXEC: zeek -b %DIR/sort-stuff.zeek common.zeek one.zeek > output1
# @TEST-EXEC: zeek -b %DIR/sort-stuff.zeek common.zeek two.zeek > output2
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff output2
# @TEST-EXEC: diff output1 output2

# the first test writes out the sqlite files...

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

@TEST-START-FILE one.zeek

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
	r["a"] = testrec($a=1, $b="b", $c=vector("elem1", "elem2"));
	r["a"] = testrec($a=1, $b="c", $c=vector("elem1", "elem2"));
	r["b"] = testrec($a=2, $b="d", $c=vector("elem1", "elem2"));
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}

@TEST-END-FILE
@TEST-START-FILE two.zeek

# the second one reads them in again

event zeek_init()
	{
	tablestore = Broker::create_master("table", Broker::SQLITE);
	setstore = Broker::create_master("set", Broker::SQLITE);
	recordstore = Broker::create_master("rec", Broker::SQLITE);
	print sort_table(t);
	print sort_set(s);
	print sort_table(r);
	}
@TEST-END-FILE
