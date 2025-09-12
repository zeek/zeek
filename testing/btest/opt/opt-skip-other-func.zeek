# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-opt-func=my_tes %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that if we exclude a different function (given function matches
# have to be full), we still compile this one.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
