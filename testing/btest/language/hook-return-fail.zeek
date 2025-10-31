# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_hook: hook();

hook myhook()
	{
	return 1;
	}

hook myhook()
	{
	# Even though hooks return a boolean when called, they should not
	# be able to return the value themselves. It would be ignored.
	return T;
	}
