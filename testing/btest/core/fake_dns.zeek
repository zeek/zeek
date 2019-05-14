# @TEST-EXEC: BRO_DNS_FAKE=1 zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

global addrs: set[addr] = {
	google.com,
	bing.com,
	yahoo.com
};

global c: count = 0;

function check_terminate()
	{
	++c;

	if ( c > 2 )
		terminate();
	}

event zeek_init()
	{
	print addrs;

	when ( local result = lookup_hostname_txt("bro.wp.dg.cx") )
		{
		print "lookup_hostname_txt", result;
		check_terminate();
		}
	when ( local result2 = lookup_hostname("example.com") )
		{
		print "lookup_hostname", result2;
		check_terminate();
		}
	when ( local result3 = lookup_addr(1.2.3.4) )
		{
		print "lookup_addr", result3;
		check_terminate();
		}
	}
