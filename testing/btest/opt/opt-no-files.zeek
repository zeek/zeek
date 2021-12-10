# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files='Xopt-files' %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Make sure that if --optimize-files is specified but there are no matching
# files, that's caught as an error.

event zeek_init()
	{
	print zeek_init;
	}
