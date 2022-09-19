# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-files='base/utils' --optimize-files='opt-files3' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a group of files *and* this one.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	print set_to_regex;
	}
