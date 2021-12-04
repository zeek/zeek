# @TEST-EXEC: zeek -b -O ZAM --optimize-func='my_test' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively a given function.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	print zeek_init;
	}
