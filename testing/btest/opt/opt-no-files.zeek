# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files=Xopt-files %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# Make sure that if --optimize-files is specified but there are no matching
# files, that's caught as an error.

event zeek_init()
	{
	print zeek_init;
	}
