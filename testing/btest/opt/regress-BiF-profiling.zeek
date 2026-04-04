# @TEST-DOC: Regression test for flawed profiling of BiFs when using --optimize-file
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM --optimize-file=regress %INPUT >output
# @TEST-EXEC: btest-diff output

option foo = 3;

event zeek_init()
	{
	print foo;
	Config::set_value("foo", 9);

	# This used to print 3 because optimizer didn't see call to Option::set
	# made by Config::set_value.
	print foo;
	}
