# @TEST-EXEC: btest-bg-run test1 zeek %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: mv test1/.stdout out
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

event zeek_init()
{
	local h: addr = 127.0.0.1;

	when ( local hname = lookup_addr(h) )
		{ 
		print "lookup successful";
		terminate();
		}
	timeout 10sec
		{
		print "timeout (1)";
		}

	local to = 5sec;
	# Just checking that timeouts can use arbitrary expressions...
	when ( local hname2 = lookup_addr(h) ) {}
	timeout to {}
	when ( local hname3 = lookup_addr(h) ) {}
	timeout to + 2sec {}

	print "done";
}

