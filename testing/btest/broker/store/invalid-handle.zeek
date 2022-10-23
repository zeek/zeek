# This crashes with ZAM because it explicitly violates typing, which happens
# to work in the interpreter, but isn't sound.
#
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function print_keys(a: any)
	{
	when [a] ( local s = Broker::keys(a) )
		{
		print "keys", s;
		}
	timeout 2sec
		{
		print fmt("<timeout for print keys>");
		}
	}

function checkit(a: any)
	{
	if ( Broker::is_closed(a) )
		print "this shouldn't get printed";
	else
		print "this shouldn't get printed either";
	}

global a: int = 0;

event zeek_init() &priority=10
	{
	checkit(a);
	}

event zeek_init()
	{
	print_keys(a);
	}
