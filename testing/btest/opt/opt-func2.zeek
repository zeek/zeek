# @TEST-EXEC: zeek -b -O ZAM --optimize-func='zeek_init' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively a bunch of functions (event handlers),
# but not every function.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	print zeek_init;
	}
