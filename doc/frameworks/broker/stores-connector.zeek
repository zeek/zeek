redef exit_only_after_terminate = T;

global h: opaque of Broker::Store;

global ready: event();

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event zeek_init()
	{
	h = Broker::create_master("mystore");

	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	Broker::put(h, "one", 110);
	Broker::put(h, "two", 223);
	Broker::put(h, "myset", myset);
	Broker::put(h, "myvec", myvec);
	Broker::increment(h, "one");
	Broker::decrement(h, "two");
	Broker::insert_into_set(h, "myset", "d");
	Broker::remove_from(h, "myset", "b");
	Broker::push(h, "myvec", "delta");

	Broker::peer("127.0.0.1");
	}
