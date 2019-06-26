# @TEST-EXEC: zeek -b %INPUT RUN=1 >out
# @TEST-EXEC: zeek -b %INPUT RUN=2 >>out
# @TEST-EXEC: btest-diff out

global RUN = 0 &redef;

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Store;

function print_index(k: any)
	{
	when ( local r = Broker::get(h, k) )
		{
		print k, r$status, r$result;
		}
	timeout query_timeout
		{
		print fmt("<timeout for %s>", k);
		}
	}

event done()
	{
	terminate();
	}

event zeek_init()
	{
	h = Broker::create_master("master", Broker::SQLITE);

	print "Run", RUN;
	
	if ( RUN == 1 ) 
		{
		print "Inserting";
		Broker::put(h, "one", "110");
		Broker::put(h, "two", 220);
		Broker::put(h, "three", 330);
		Broker::put(h, "four", set(1, 2,3));
		Broker::put(h, set("x", "y"), vector(1/tcp, 2/tcp, 3/tcp));
		terminate();
		}

	if ( RUN == 2 )
		{
		print "Retrieving";
		print_index("one");
		print_index("two");
		print_index("three");
		print_index("four");
		print_index("five");
		print_index(set("x", "y"));
		}

        schedule 2secs { done() };
	}
