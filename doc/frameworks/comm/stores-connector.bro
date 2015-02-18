const broker_port: port &redef;
redef exit_only_after_terminate = T;

global h: opaque of Store::Handle;

function dv(d: Comm::Data): Comm::DataVector
	{
	local rval: Comm::DataVector;
	rval[0] = d;
	return rval;
	}

global ready: event();

event Comm::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}

event Comm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = Store::create_master("mystore");
	Store::insert(h, Comm::data("one"), Comm::data(110));
	Store::insert(h, Comm::data("two"), Comm::data(223));
	Store::insert(h, Comm::data("myset"), Comm::data(myset));
	Store::insert(h, Comm::data("myvec"), Comm::data(myvec));
	Store::increment(h, Comm::data("one"));
	Store::decrement(h, Comm::data("two"));
	Store::add_to_set(h, Comm::data("myset"), Comm::data("d"));
	Store::remove_from_set(h, Comm::data("myset"), Comm::data("b"));
	Store::push_left(h, Comm::data("myvec"), dv(Comm::data("delta")));
	Store::push_right(h, Comm::data("myvec"), dv(Comm::data("omega")));

	when ( local res = Store::size(h) )
		{
		print "master size", res;
		event ready();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	Comm::enable();
	Comm::connect("127.0.0.1", broker_port, 1secs);
	Comm::auto_event("bro/event/ready", ready);
	}
