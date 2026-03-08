# @TEST-EXEC: ZEEK_DNS_FAKE=1 zeek -D -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

redef exit_only_after_terminate = T;

global addrs: set[addr] = {
	blocking_lookup_hostname("google.com"),
	blocking_lookup_hostname("bing.com"),
	blocking_lookup_hostname("yahoo.com")
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
