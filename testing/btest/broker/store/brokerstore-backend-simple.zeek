# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run master "zeek -B broker -b ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run clone "zeek -B broker -b ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-wait 15
#
# @TEST-EXEC: btest-diff clone.out

@TEST-START-FILE master.zeek
redef exit_only_after_terminate = T;

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &backend=Broker::MEMORY;

event zeek_init()
	{
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event insert_stuff()
	{
	print "Inserting stuff";
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
	print t;
	print s;
	print r;
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added ", endpoint;
  schedule 3secs { insert_stuff() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE clone.zeek
redef exit_only_after_terminate = T;
redef Broker::auto_store_master = F;

module TestModule;

type testrec: record {
	a: count;
	b: string;
	c: set[string];
};

global t: table[string] of count &backend=Broker::MEMORY;
global s: set[string] &backend=Broker::MEMORY;
global r: table[string] of testrec &backend=Broker::MEMORY;


event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event dump_tables()
	{
	print t;
	print s;
	print r;
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Peer added";
	schedule 5secs { dump_tables() };
	}
@TEST-END-FILE
