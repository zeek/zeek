# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files=my_func %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# Make sure that if --optimize-func is specified but there are no matching
# functions, that's caught as an error.

event zeek_init()
	{
	print zeek_init;
	}
