# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local bro -m -r $TRACES/wikipedia.trace %INPUT

const foo: set[addr] = {
     google.com
};

# Add the state tracking information variable to the connection record

event connection_established(c: connection)
	{
	when ( local addrs = lookup_hostname("localhost") )
		{
		print "1a", c$id$resp_h, addrs;
		}
	timeout 100secs
		{
		print "1b", c$id$resp_h;
		}

	when ( local addrs2 = lookup_hostname("qq.ww.ee.rrrrr") )
		{
		print "2a", c$id$resp_h, addrs2;
		}
	timeout 100secs
		{
		print "2b", c$id$resp_h;
		}

	when ( local a = lookup_addr(c$id$resp_h) )
		{
		print "3a", c$id$resp_h, a;
		}
	timeout 100secs
		{
		print "3b", c$id$resp_h;
		}

	when ( local a2 = lookup_addr(1.2.3.4) )
		{
		print "4a", c$id$resp_h, a2;
		}
	timeout 100secs
		{
		print "4b", c$id$resp_h;
		}
		
	}

