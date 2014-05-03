# @TEST-EXEC: unset BRO_DNS_FAKE && bro -b %INPUT >out
# @TEST-EXEC: btest-diff out


event bro_init()
{
	local h1: addr = 1.2.3.4;

	when ( local h1name = lookup_addr(h1) )
		{ 
		print "lookup successful";
		}
	timeout 3 secs
		{
		print "timeout";
		}

}

