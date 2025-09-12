# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-opt-func=my_test %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively exclude a function.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
