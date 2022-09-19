# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-func='my_test' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a given function.

function my_test()
	{
	print "I should be ZAM code!";
	}

function another_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	another_test();
	print my_test;
	print another_test;
	}
