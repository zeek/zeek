# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

redef exit_only_after_terminate = T;

const foo: set[addr] = {
     google.com
};

global n1 = 0;
global n2 = 0;
global n3 = 0;
global n4 = 0;

function check_term_conditions()
	{
	if ( n1 > 4 && n2 > 4 && n3 > 4 && n4 > 4  )
		terminate();
	}

event connection_established(c: connection)
	{
	when ( local addrs = lookup_hostname("localhost") )
		{
		print "1a", c$id$resp_h, addrs;
		++n1;
		check_term_conditions();
		}
	timeout 100secs
		{
		print "1b", c$id$resp_h;
		++n1;
		check_term_conditions();
		}

	when ( local addrs2 = lookup_hostname("qq.ww.ee.rrrrr") )
		{
		print "2a", c$id$resp_h, addrs2;
		++n2;
		check_term_conditions();
		}
	timeout 100secs
		{
		print "2b", c$id$resp_h;
		++n2;
		check_term_conditions();
		}

	when ( local a = lookup_addr(c$id$resp_h) )
		{
		print "3a", c$id$resp_h, a;
		++n3;
		check_term_conditions();
		}
	timeout 100secs
		{
		print "3b", c$id$resp_h;
		++n3;
		check_term_conditions();
		}

	when ( local a2 = lookup_addr(1.2.3.4) )
		{
		print "4a", c$id$resp_h, a2;
		++n4;
		check_term_conditions();
		}
	timeout 100secs
		{
		print "4b", c$id$resp_h;
		++n4;
		check_term_conditions();
		}
	}

