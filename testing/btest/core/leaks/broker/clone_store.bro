# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks
# @TEST-GROUP: leak

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run clone "bro -m -b ../clone.bro broker_port=$BROKER_PORT >clone.out"
# @TEST-EXEC: btest-bg-run master "bro -b ../master.bro broker_port=$BROKER_PORT >master.out"

# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff clone/clone.out

@TEST-START-FILE clone.bro

const broker_port: port &redef;
redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;
global expected_key_count = 4;
global key_count = 0;

function do_lookup(key: string)
	{
	when ( local res = BrokerStore::lookup(h, BrokerComm::data(key)) )
		{
		++key_count;
		print "lookup", key, res;

		if ( key_count == expected_key_count )
			terminate();
		}
	timeout 10sec
		{ print "timeout"; }
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
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::listen(broker_port, "127.0.0.1");
	BrokerComm::subscribe_to_events("bro/event/ready");
	}

@TEST-END-FILE

@TEST-START-FILE master.bro

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
	timeout 10sec
		{ print "timeout"; }
	}

event bro_init()
	{
	BrokerComm::enable();
	h = BrokerStore::create_master("mystore");
	BrokerComm::connect("127.0.0.1", broker_port, 1secs);
	BrokerComm::auto_event("bro/event/ready", ready);
	}

@TEST-END-FILE
