# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --no-optimize-files=Xopt-skip-other-file %INPUT >out1
# @TEST-EXEC: zeek -b -O ZAM --no-optimize-func=my_tes %INPUT >out2
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2

# The first test checks that if we exclude a different file, we still compile
# this one.  The second tests that if we exclude a different function (since
# function matches have to be full), we still compile this one.

function my_test()
	{
	print "I should be ZAM code!";
	}

event zeek_init()
	{
	my_test();
	print my_test;
	}
