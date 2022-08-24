# The default is for an initialization error to be a hard failure.

# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS && zeek -b %INPUT >out 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

event zeek_init() &priority=10
	{
	print "1st event";
	}

event zeek_init()
	{
	print "2nd event";
	local v = vector(1, 2, 3);
	print v[10];
	}

event zeek_init() &priority=-10
	{
	print "3rd event";
	}
