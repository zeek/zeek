# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-optimize-func=my_test %INPUT >out1
# @TEST-EXEC: zeek -b -O ZAM --no-optimize-func=my_test --optimize-func=my_test %INPUT --optimize-func=zeek_init >out2
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2

# The first test checks that we can selectively exclude a function.
# The second tests that skipping overrides including.

function my_test()
	{
	print "I shouldn't be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
