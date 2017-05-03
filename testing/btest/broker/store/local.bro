# @TEST-EXEC: btest-bg-run master "bro -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Handle;

function do_lookup(key: string)
	{
	when ( local res = Broker::get(h, key) )
		{
		print fmt("lookup(%s): %s", key, res);
		}
	timeout query_timeout
		{
		print "'lookup' query timeout";
		}
	}

function dv(d: Broker::Data): Broker::DataVector
	{
	local rval: Broker::DataVector;
	rval[0] = d;
	return rval;
	}

event done()
	{
	terminate();
	}

event bro_init()
	{
	local myset: set[string] = {"a", "b", "c"};
	local myvec: vector of string = {"alpha", "beta", "gamma"};

	h = Broker::create_master("master");
	Broker::put(h, "one", 110);
	Broker::put(h, "two", 223);

	do_lookup("one");
	do_lookup("two");
        
#	do_lookup("one");
#	do_lookup("two");
#	do_lookup("myset");
#	do_lookup("four");
#	do_lookup("myvec");
#       
        schedule 5secs { done() };
	}
