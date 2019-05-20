# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

redef exit_only_after_terminate = T;

global n1 = 0;

function check_term_conditions()
	{
	if ( n1 > 7 )
		terminate();
	}


event do_txt(s: string)
	{
	when ( local t1 = lookup_hostname_txt(s) )
		{
		print "t1", t1;
		++n1;
		check_term_conditions();
		}
	timeout 100secs
		{
		print "t1 timeout";
		++n1;
		check_term_conditions();
		}
	}

event connection_established(c: connection)
	{
	event do_txt("localhost");
	schedule 5sec { do_txt("localhost") };
	}

