# @TEST-EXEC: btest-bg-run master "bro -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Handle;

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

event done()
	{
	terminate();
	}

event bro_init()
	{
	h = Broker::create_master("master");
	Broker::put(h, "one", "110");
	Broker::put(h, "two", 220);
	Broker::put(h, "three", 330);
	Broker::put(h, "four", set(1, 2,3));
	Broker::put(h, set("x", "y"), vector(1/tcp, 2/tcp, 3/tcp));

	print_index("one");
	print_index("two");
	print_index("three");
	print_index("four");
	print_index("five");
	print_index(set("x", "y"));

	when ( step == 6 )
		{
		Broker::erase(h, "four");
		Broker::add_(h, "two");
		Broker::add_(h, "two", 9);
		Broker::subtract(h, "three");
		Broker::subtract(h, "three", 9);
		print_index("two");
		print_index("three");
		print_index("four");
		}

        schedule 2secs { done() };
	}
