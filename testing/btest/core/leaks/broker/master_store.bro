# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks
# @TEST-GROUP: leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff bro/.stdout

redef exit_only_after_terminate = T;

global h: opaque of BrokerStore::Handle;
global lookup_count = 0;
const lookup_expect_count = 5;
global exists_count = 0;
const exists_expect_count = 4;
global pop_count = 0;
const pop_expect_count = 2;

global test_size: event(where: string &default = "");

event test_clear()
	{
	BrokerStore::clear(h);
	event test_size("after clear");
	}

event test_size(where: string)
	{
	when ( local res = BrokerStore::size(h) )
		{
		if ( where == "" )
			{
			print fmt("size: %s", res);
			event test_clear();
			}
		else
			{
			print fmt("size (%s): %s", where, res);
			terminate();
			}
		}
	timeout 10sec
		{ print "timeout"; }
	}

event test_keys()
	{
	when ( local res = BrokerStore::keys(h) )
		{
		print fmt("keys: %s", res);
		event test_size();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event test_pop(key: string)
	{
	when ( local lres = BrokerStore::pop_left(h, BrokerComm::data(key)) )
		{
		print fmt("pop_left(%s): %s", key, lres);
		++pop_count;

		if ( pop_count == pop_expect_count )
			event test_keys();
		}
	timeout 10sec
		{ print "timeout"; }

	when ( local rres = BrokerStore::pop_right(h, BrokerComm::data(key)) )
		{
		print fmt("pop_right(%s): %s", key, rres);
		++pop_count;

		if ( pop_count == pop_expect_count )
			event test_keys();
		}
	timeout 10sec
		{ print "timeout"; }
	}

function do_exists(key: string)
	{
	when ( local res = BrokerStore::exists(h, BrokerComm::data(key)) )
		{
		print fmt("exists(%s): %s", key, res);
		++exists_count;

		if ( exists_count == exists_expect_count )
			event test_pop("myvec");
		}
	timeout 10sec
		{ print "timeout"; }
	}

event test_erase()
	{
	BrokerStore::erase(h, BrokerComm::data("two"));
	do_exists("one");
	do_exists("two");
	do_exists("myset");
	do_exists("four");
	}

function do_lookup(key: string)
	{
	when ( local res = BrokerStore::lookup(h, BrokerComm::data(key)) )
		{
		print fmt("lookup(%s): %s", key, res);
		++lookup_count;

		if ( lookup_count == lookup_expect_count )
			event test_erase();
		}
	timeout 10sec
		{ print "timeout"; }
	}

function dv(d: BrokerComm::Data): BrokerComm::DataVector
	{
	local rval: BrokerComm::DataVector;
	rval[0] = d;
	return rval;
	}

global did_it = F;

event bro_init()
	{
	BrokerComm::enable();
	h = BrokerStore::create_master("master");
	}

event new_connection(c: connection)
	{
	if ( did_it ) return;
	did_it = T;
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
	do_lookup("one");
	do_lookup("two");
	do_lookup("myset");
	do_lookup("four");
	do_lookup("myvec");
	}
