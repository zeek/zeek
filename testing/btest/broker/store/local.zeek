# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

redef exit_only_after_terminate = T;

global query_timeout = 1sec;

global h: opaque of Broker::Store;

event done()
	{
	terminate();
	}

event zeek_init()
	{
	h = Broker::create_master("master");
	Broker::put(h, "one", "110");
	Broker::put(h, "two", 223);

	when ( local res1 = Broker::get(h, "one") )
		{
		local s = (res1$result as string);
		print "string", s;
		}
	timeout query_timeout 
		{
		print "timeout";
		}

	when ( local res2 = Broker::get(h, "two") )
		{
		local c = (res2$result as count);
		print "count", c;
		}
	timeout query_timeout 
		{
		print "timeout";
		}
	
        schedule 2secs { done() };
	}
