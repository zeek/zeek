# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-opt-files=Xopt-skip-other-file %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that if we exclude a different file, we still compile this one.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
