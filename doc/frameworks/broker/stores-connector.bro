const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;

function dv(d: BrokerComm::Data): BrokerComm::DataVector
	{
	local rval: BrokerComm::DataVector;
	rval[0] = d;
	return rval;
	}

global ready: event();

event BrokerComm::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}

event BrokerComm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = BrokerStore::create_master("mystore");
	BrokerStore::insert(h, BrokerComm::data("one"), BrokerComm::data(110));
	BrokerStore::insert(h, BrokerComm::data("two"), BrokerComm::data(223));
	BrokerStore::insert(h, BrokerComm::data("myset"), BrokerComm::data(myset));
	BrokerStore::insert(h, BrokerComm::data("myvec"), BrokerComm::data(myvec));
	BrokerStore::increment(h, BrokerComm::data("one"));
	BrokerStore::decrement(h, BrokerComm::data("two"));
	BrokerStore::add_to_set(h, BrokerComm::data("myset"), BrokerComm::data("d"));
	BrokerStore::remove_from_set(h, BrokerComm::data("myset"), BrokerComm::data("b"));
	BrokerStore::push_left(h, BrokerComm::data("myvec"), dv(BrokerComm::data("delta")));
	BrokerStore::push_right(h, BrokerComm::data("myvec"), dv(BrokerComm::data("omega")));

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
	BrokerComm::enable();
	BrokerComm::connect("127.0.0.1", broker_port, 1secs);
	BrokerComm::auto_event("bro/event/ready", ready);
	}
