# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-optimize-files=opt-skip-files %INPUT >output
# @TEST-EXEC-FAIL: zeek -b -O ZAM --no-optimize-files=opt-skip-files --optimize-files=opt-skip-files %INPUT
# @TEST-EXEC: btest-diff output

# The first run tests that we can selectively exclude this file.
#
# The second run tests that skipping overrides including. This should
# result in an error because there are no functions to compile.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
