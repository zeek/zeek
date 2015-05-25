# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt

# @TEST-EXEC: btest-bg-run clone "bro -b -r $TRACES/wikipedia.trace ../clone.bro broker_port=$BROKER_PORT >clone.out"
# @TEST-EXEC: btest-bg-run master "bro -b -r $TRACES/wikipedia.trace ../master.bro broker_port=$BROKER_PORT >master.out"

# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff clone/clone.out
# @TEST-EXEC: btest-diff master/master.out

@TEST-START-FILE clone.bro

const broker_port: port &redef;
redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;
global expected_key_count = 4;
global key_count = 0;

global query_timeout = 30sec;

function do_lookup(key: string)
	{
	when ( local res = BrokerStore::lookup(h, BrokerComm::data(key)) )
		{
		++key_count;
		print "lookup", key, res;

		if ( key_count == expected_key_count )
			terminate();
		}
	timeout query_timeout
		{
		print "clone lookup query timeout";
		terminate();
		}
	}

event ready()
	{
	h = BrokerStore::create_clone("mystore");

	when ( local res = BrokerStore::keys(h) )
		{
		print "clone keys", res;
		do_lookup(BrokerComm::refine_to_string(BrokerComm::vector_lookup(res$result, 0)));
		do_lookup(BrokerComm::refine_to_string(BrokerComm::vector_lookup(res$result, 1)));
		do_lookup(BrokerComm::refine_to_string(BrokerComm::vector_lookup(res$result, 2)));
		do_lookup(BrokerComm::refine_to_string(BrokerComm::vector_lookup(res$result, 3)));
		}
	timeout query_timeout
		{
		print "clone keys query timeout";
		terminate();
		}
	}

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/ready");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

@TEST-END-FILE

@TEST-START-FILE master.bro

global query_timeout = 15sec;

const broker_port: port &redef;
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
		{ event ready(); }
	timeout query_timeout
		{
		print "master size query timeout";
		terminate();
		}
	}

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::auto_event("bro/event/ready", ready);
	BrokerComm::connect("127.0.0.1", broker_port, 1secs);
	}

@TEST-END-FILE
