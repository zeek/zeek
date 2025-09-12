# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC-FAIL: zeek -b -O ZAM --no-opt-files=opt-skip-files --optimize-files=opt-skip-files %INPUT >output

# Tests that skipping overrides including. This should result in an error
# because there are no functions to compile.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
