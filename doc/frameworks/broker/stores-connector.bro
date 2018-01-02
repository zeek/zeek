redef exit_only_after_terminate = T;

global h: opaque of Broker::Store;

global ready: event();

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = Broker::create_master("mystore");
	Broker::put(h, "one", 110);
	Broker::put(h, "two", 223);
	Broker::put(h, "myset", myset);
	Broker::put(h, "myvec", myvec);
	Broker::increment(h, "one");
	Broker::decrement(h, "two");
	Broker::insert_into_set(h, "myset", "d");
	Broker::remove_from(h, "myset", "b");
	Broker::push(h, "myvec", "delta");

	when ( local res = Broker::exists(h, "myvec") )
		{
		print "master ready", res;
		event ready();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	Broker::peer("127.0.0.1");
	Broker::auto_publish("bro/event/ready", ready);
	}
