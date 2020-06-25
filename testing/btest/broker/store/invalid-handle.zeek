# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function print_keys(a: any)
	{
	when ( local s = Broker::keys(a) )
		{
		print "keys", s;
		}
	timeout 2sec
		{
		print fmt("<timeout for print keys>");
		}
	}

global a: int = 0;

event zeek_init()
	{
	print_keys(a);
	}
