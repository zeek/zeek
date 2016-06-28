# @TEST-REQUIRES: grep -q ENABLE_BROKER:BOOL=true $BUILD/CMakeCache.txt
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks
# @TEST-GROUP: leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff bro/.stdout

redef exit_only_after_terminate = T;

global h: opaque of Broker::Handle;
global lookup_count = 0;
const lookup_expect_count = 5;
global exists_count = 0;
const exists_expect_count = 4;
global pop_count = 0;
const pop_expect_count = 2;

global test_size: event(where: string &default = "");

event test_clear()
	{
	Broker::clear(h);
	event test_size("after clear");
	}

event test_size(where: string)
	{
	when ( local res = Broker::size(h) )
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
	when ( local res = Broker::keys(h) )
		{
		print fmt("keys: %s", res);
		event test_size();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event test_pop(key: string)
	{
	when ( local lres = Broker::pop_left(h, Broker::data(key)) )
		{
		print fmt("pop_left(%s): %s", key, lres);
		++pop_count;

		if ( pop_count == pop_expect_count )
			event test_keys();
		}
	timeout 10sec
		{ print "timeout"; }

	when ( local rres = Broker::pop_right(h, Broker::data(key)) )
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
	when ( local res = Broker::exists(h, Broker::data(key)) )
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
	Broker::erase(h, Broker::data("two"));
	do_exists("one");
	do_exists("two");
	do_exists("myset");
	do_exists("four");
	}

function do_lookup(key: string)
	{
	when ( local res = Broker::lookup(h, Broker::data(key)) )
		{
		print fmt("lookup(%s): %s", key, res);
		++lookup_count;

		if ( lookup_count == lookup_expect_count )
			event test_erase();
		}
	timeout 10sec
		{ print "timeout"; }
	}

function dv(d: Broker::Data): Broker::DataVector
	{
	local rval: Broker::DataVector;
	rval[0] = d;
	return rval;
	}

global did_it = F;

event bro_init()
	{
	Broker::enable();
	h = Broker::create_master("master");
	}

event new_connection(c: connection)
	{
	if ( did_it ) return;
	did_it = T;
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	Broker::insert(h, Broker::data("one"), Broker::data(110));
	Broker::insert(h, Broker::data("two"), Broker::data(223));
	Broker::insert(h, Broker::data("myset"), Broker::data(myset));
	Broker::insert(h, Broker::data("myvec"), Broker::data(myvec));
	Broker::increment(h, Broker::data("one"));
	Broker::decrement(h, Broker::data("two"));
	Broker::add_to_set(h, Broker::data("myset"), Broker::data("d"));
	Broker::remove_from_set(h, Broker::data("myset"), Broker::data("b"));
	Broker::push_left(h, Broker::data("myvec"), dv(Broker::data("delta")));
	Broker::push_right(h, Broker::data("myvec"), dv(Broker::data("omega")));
	do_lookup("one");
	do_lookup("two");
	do_lookup("myset");
	do_lookup("four");
	do_lookup("myvec");
	}
