# @TEST-EXEC: btest-bg-run master "zeek -B broker -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Store;

global step: count = 0;

function print_index(k: any)
	{
	when ( local r = Broker::get(h, k) )
		{
		step += 1;
		print fmt("[%d]", step), k, r$status, r$result;
		}
	timeout query_timeout
		{
		step += 1;
		print fmt("[%d] <timeout for %s>", step, k);
		}
	}

function print_exists(k: any)
	{
	when ( local r = Broker::exists(h, k) )
		{
		step += 1;
		print fmt("[%d]", step), k, r;
		}
	timeout query_timeout
		{
		step += 1;
		print fmt("[%d] <timeout for %s>", step, k);
		}
	}

function print_index_from_value(k: any, i: any)
	{
	when ( local r = Broker::get_index_from_value(h, k, i) )
		{
		step += 1;
		print fmt("[%d]", step), k, r$status, r$result;
		}
	timeout query_timeout
		{
		step += 1;
		print fmt("[%d] <timeout for %s>", step, k);
		}
	}

function print_keys()
	{
	when ( local s = Broker::keys(h) )
		{
		step += 1;
		print "keys", s;
		}
	timeout query_timeout
		{
		step += 1;
		print fmt("[%d] <timeout for print keys>", step);
		}
	}

event done()
	{
	terminate();
	}

event pk2()
	{
	print_keys();
	}

event pk1()
	{
	print_keys();
	Broker::clear(h);
	schedule 1sec { pk2() };
	}

event zeek_init()
	{
	h = Broker::create_master("master");
	Broker::put(h, "one", "110");
	Broker::put(h, "two", 220);
	Broker::put(h, "three", 330);
	Broker::put(h, "four", set(1, 2,3));
	Broker::put(h, set("x", "y"), vector(1/tcp, 2/tcp, 3/tcp));

	Broker::put(h, "str", "foo");
	Broker::put(h, "vec", vector(1, 2,3));
	Broker::put(h, "set", set("A", "B"));
	Broker::put(h, "table", table(["a"] = 1, ["b"] = 2));
	
	print_index("one");
	print_index("two");
	print_index("three");
	print_index("four");
	print_index("five");
	print_index(set("x", "y"));

	when ( step == 6 )
		{
		Broker::increment(h, "two");
		Broker::increment(h, "two", 9);
		Broker::decrement(h, "three");
		Broker::decrement(h, "three", 9);
		print_index("two");
		print_index("three");
		print_index("four");
		print_keys();
		Broker::erase(h, "four");

		Broker::append(h, "str", "bar");
		Broker::insert_into_set(h, "set", "C");
		Broker::insert_into_table(h, "table", "c", 3);
		Broker::remove_from(h, "set", 2);
		Broker::remove_from(h, "table", "b");
		Broker::push(h, "vec", 4);
		Broker::push(h, "vec", 5);
		Broker::pop(h, "vec");

		print_index("str");
		print_index("set");
		print_index("table");
		print_index("vec");

		print_exists("one");
		print_exists("NOPE");
	
        	print_index_from_value("vec", 1);
        	print_index_from_value("set", "A");
    	        print_index_from_value("table", "a");
    	        print_index_from_value("table", "X");
		
		schedule 1sec { pk1() };
		}

        schedule 4secs { done() };
	}
