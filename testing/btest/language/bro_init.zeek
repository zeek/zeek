# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event bro_init()
	{
	print "ran bro_init()";
	}

event bro_done()
	{
	print "ran bro_done()";
	}
