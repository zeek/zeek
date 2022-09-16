# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-files='opt-files' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick this file.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
