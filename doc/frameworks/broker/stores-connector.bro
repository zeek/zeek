const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;

function dv(d: Broker::Data): Broker::DataVector
	{
	local rval: Broker::DataVector;
	rval[0] = d;
	return rval;
	}

global ready: event();

event Broker::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}

event Broker::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = BrokerStore::create_master("mystore");
	BrokerStore::insert(h, Broker::data("one"), Broker::data(110));
	BrokerStore::insert(h, Broker::data("two"), Broker::data(223));
	BrokerStore::insert(h, Broker::data("myset"), Broker::data(myset));
	BrokerStore::insert(h, Broker::data("myvec"), Broker::data(myvec));
	BrokerStore::increment(h, Broker::data("one"));
	BrokerStore::decrement(h, Broker::data("two"));
	BrokerStore::add_to_set(h, Broker::data("myset"), Broker::data("d"));
	BrokerStore::remove_from_set(h, Broker::data("myset"), Broker::data("b"));
	BrokerStore::push_left(h, Broker::data("myvec"), dv(Broker::data("delta")));
	BrokerStore::push_right(h, Broker::data("myvec"), dv(Broker::data("omega")));

	when ( local res = BrokerStore::size(h) )
		{
		print "master size", res;
		event ready();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	Broker::enable();
	Broker::connect("127.0.0.1", broker_port, 1secs);
	Broker::auto_event("bro/event/ready", ready);
	}
