# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-files='base/utils' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a group of files but not this one.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	print set_to_regex;
	}
