# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -B broker -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -B broker -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

type myvec: vector of any;

type myrec: record {
	a: string &optional;
	b: count &optional;
	c: int &optional;
};

global bar: event(x: any);

event zeek_init()
	{
	Broker::subscribe("test");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	Broker::publish("test", bar, 1);
	Broker::publish("test", bar, "two");
	Broker::publish("test", bar, myvec("one", "two", 3));
	Broker::publish("test", bar, myrec($a = "bye"));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

type myvec: vector of any;

type myrec: record {
	a: string &optional;
	b: count &optional;
	c: int &optional;
};

function process(x: any)
	{
	switch ( x ) {
	case type myrec as r:
		print "record", r;

		if ( r$a == "bye" )
			terminate();

		break;
	case type string as s:
		print "string", s;
		break;
	case type int as i:
		print "int", i;
		break;
	case type count as c:
		print "count", c;
		break;
	case type myvec as v:
		{
		print "vector", v;

		for ( i in v )
			process(v[i]);
		}
		break;
	default:
		print "got unknown type", x;
		break;
	}
	}

event bar(x: any)
	{
	process(x);
	}

event zeek_init()
	{
	Broker::subscribe("test");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE
