# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "ZEEK_COMPILE_ALL=1 zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out

@TEST-START-FILE common.zeek
redef exit_only_after_terminate = T;

type MyRecord: record {
	a: count;
	b: string;
};

type MyVector: vector of string;

type MyOpaque: opaque of topk;

type MyFunction: function();

function foo()
	{ print "foo"; }

type Set1: set[count];
type Set2: set[count, string];
type SetVector: set[MyVector];
type SetRecord: set[MyRecord];
type SetFunction: set[MyFunction];
type SetPattern: set[pattern];

type Table1: table[count] of string;
type Table2: table[count, string] of string;
type TableVector: table[MyVector] of string;
type TableRecord: table[MyRecord] of string;
type TableFunction: table[MyFunction] of string;
type TablePattern: table[pattern] of string;

global set1: event(x: Set1);
global set2: event(x: Set2);
global setvector: event(x: SetVector);
global setrecord: event(x: SetRecord);
global setfunction: event(x: SetFunction);
global setpattern: event(x: SetPattern);

global table1: event(x: Table1);
global table2: event(x: Table2);
global tablevector: event(x: TableVector);
global tablerecord: event(x: TableRecord);
global tablefunction: event(x: TableFunction);
global tablepattern: event(x: TablePattern);

global done: event();
@TEST-END-FILE

@TEST-START-FILE send.zeek
@load ./common.zeek

event zeek_init()
	{ Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT"))); }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	Broker::publish("test", set1, Set1(1));
	Broker::publish("test", set2, Set2([2, "two"]));
	Broker::publish("test", setvector, SetVector(MyVector("one", "two")));
	Broker::publish("test", setrecord, SetRecord(MyRecord($a=97, $b="B")));
	Broker::publish("test", setfunction, SetFunction(foo));
	Broker::publish("test", setpattern, SetPattern(/foobar/));

	Broker::publish("test", table1, Table1([1] = "t1"));
	Broker::publish("test", table2, Table2([2, "two"] = "t2"));
	Broker::publish("test", tablevector, TableVector([MyVector("one", "two")] = "tvec"));
	Broker::publish("test", tablerecord, TableRecord([MyRecord($a=97, $b="B")] = "trec"));
	Broker::publish("test", tablefunction, TableFunction([foo] = "tfunc"));
	Broker::publish("test", tablepattern, TablePattern([/foobar/] = "tpat"));

	Broker::publish("test", done);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{ terminate(); }
@TEST-END-FILE

@TEST-START-FILE recv.zeek
@load ./common.zeek

event set1(x: Set1)
	{ print "set1", x; }
event set2(x: Set2)
	{ print "set2", x; }
event setvector(x: SetVector)
	{ print "setvector", x; }
event setrecord(x: SetRecord)
	{ print "setrecord", x; }
event setfunction(x: SetFunction)
	{ print "setfunction", x; }
event setpattern(x: SetPattern)
	{ print "setpattern", x; }

event table1(x: Table1)
	{ print "table1", x; }
event table2(x: Table2)
	{ print "table2", x; }
event tablevector(x: TableVector)
	{ print "tablevector", x; }
event tablerecord(x: TableRecord)
	{ print "tablerecord", x; }
event tablefunction(x: TableFunction)
	{ print "tablefunction", x; }
event tablepattern(x: TablePattern)
	{ print "tablepattern", x; }

event zeek_init()
	{
	Broker::subscribe("test");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event done()
	{ terminate(); }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{ terminate(); }
@TEST-END-FILE
