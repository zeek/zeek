# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files='my_func' %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Make sure that if --optimize-func is specified but there are no matching
# functions, that's caught as an error.

event zeek_init()
	{
	print zeek_init;
	}
