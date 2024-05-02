# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

type myvec: vector of any;
type mylist: list of any;

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
	Broker::publish("test", bar, mylist("four", "five", 6));
	Broker::publish("test", bar, myrec($a = "bye"));

	# A non-obvious, half-bug/half-feature of Broker and the "as"
	# operator is that with Broker, typing is not fully preserved,
	# but rather inferred. So the first of these will be received
	# as a myrec() rather than a myvec(), because it's type-compatible,
	# while the second won't.
	#
	# For a similar reason, the mylist() above is received as a myvec().

	Broker::publish("test", bar, myvec("hello", 5, -5));
	Broker::publish("test", bar, myvec("hello", 5, 5));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

type myvec: vector of any;
type mylist: list of any;

type myrec: record {
	a: string &optional;
	b: count &optional;
	c: int &optional;
};

function process(x: any)
	{
	switch ( x ) {
	# Note, if this case is moved *after* the one for myvec, then
	# this case will never execute (and thus we'll never terminate),
	# because type switches are assessed in-listed-order, and as
	# discussed above a myrec will alias with a myvec due to how
	# Broker represents records (and lists) as vectors under-the-hood.
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

	# Similarly, if we add a "case type mylist" before the following,
	# then it will be the only one executed. And if added *after* then
	# it will never execute.
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

event bar(x: any) &is_used
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
