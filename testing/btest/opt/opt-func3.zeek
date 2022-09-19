# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-func='my_test' --optimize-func='another_test' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a bunch of functions (event handlers),
# and also call out an additional function.

function my_test()
	{
	print "Me and my buds should be ZAM code!";
	}

function another_test()
	{
	print "that includes me!";
	}

event zeek_init()
	{
	my_test();
	another_test();
	print my_test;
	print another_test;
	}
