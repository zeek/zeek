# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff master/out

redef exit_only_after_terminate = T;

global tablestore: opaque of Broker::Store;

global result_count = 0;

function print_keys(a: opaque of Broker::Store)
	{
	when [a] ( local s = Broker::keys(a) )
		{
		print "keys", s;
		++result_count;

		if ( result_count == 2 )
			terminate();
		}
	timeout 2sec
		{
		print fmt("<timeout for print keys>");
		++result_count;

		if ( result_count == 2 )
			terminate();
		}
	}

event zeek_init()
	{
	tablestore = Broker::create_master("table");
	print_keys(tablestore);
	print_keys(copy(tablestore));
	}
