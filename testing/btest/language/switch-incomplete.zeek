# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	switch ( 1 ) {
	case 1:
		print 1;
		# error: neither break/fallthrough/return here.
	}
	}

