# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

redef exit_only_after_terminate = T;

global h: opaque of Store::Handle;
global lookup_count = 0;
const lookup_expect_count = 5;
global exists_count = 0;
const exists_expect_count = 4;
global pop_count = 0;
const pop_expect_count = 2;

global test_size: event(where: string &default = "");

event test_clear()
	{
	Store::clear(h);
	event test_size("after clear");
	}

event test_size(where: string)
	{
	when ( local res = Store::size(h) )
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
	when ( local res = Store::keys(h) )
		{
		print fmt("keys: %s", res);
		event test_size();
		}
	timeout 10sec
		{ print "timeout"; }
	}

event test_pop(key: string)
	{
	when ( local lres = Store::pop_left(h, Comm::data(key)) )
		{
		print fmt("pop_left(%s): %s", key, lres);
		++pop_count;

		if ( pop_count == pop_expect_count )
			event test_keys();
		}
	timeout 10sec
		{ print "timeout"; }

	when ( local rres = Store::pop_right(h, Comm::data(key)) )
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
	when ( local res = Store::exists(h, Comm::data(key)) )
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
	Store::erase(h, Comm::data("two"));
	do_exists("one");
	do_exists("two");
	do_exists("myset");
	do_exists("four");
	}

function do_lookup(key: string)
	{
	when ( local res = Store::lookup(h, Comm::data(key)) )
		{
		print fmt("lookup(%s): %s", key, res);
		++lookup_count;

		if ( lookup_count == lookup_expect_count )
			event test_erase();
		}
	timeout 10sec
		{ print "timeout"; }
	}

function dv(d: Comm::Data): Comm::DataVector
	{
	local rval: Comm::DataVector;
	rval[0] = d;
	return rval;
	}

event bro_init()
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};
	h = Store::create_master("master");
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
	do_lookup("one");
	do_lookup("two");
	do_lookup("myset");
	do_lookup("four");
	do_lookup("myvec");
	}
