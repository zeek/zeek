# @TEST-EXEC-FAIL: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global myhook: hook(s: string);

hook myhook(s: string)
	{
	print "myhook", s;
	}

event bro_init()
	{
	# hooks must be invoked with a "hook", statement.  They have no return
	# value and don't make sense to evaluate as arbitrary expressions.
	local r = myhook("nope");
	}
