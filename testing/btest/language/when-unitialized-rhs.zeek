# C++-compiled scripts don't check for missing functions - not clear it's
# worth fixing that.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global crashMe: function(): string;
global x: int;

event zeek_init()
	{
	when( local result = crashMe() )
		{
		print "1st when stmt executing", result;
		}

	when( local other_result = x )
		{
		print "2nd when stmt executing", other_result;
		}
	}

global conn_count = 0;

event new_connection(c: connection)
	{
	++conn_count;
	print conn_count;

	if ( conn_count == 10 )
		{
		x = 999;
		crashMe = function(): string { return "not anymore you don't"; };
		}
	}
