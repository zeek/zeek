# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-func='another_test' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a bunch of functions (event handlers),
# but not every function.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

function another_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	another_test();
	print my_test;
	print another_test;
	}
