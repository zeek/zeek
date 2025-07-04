# @TEST-DOC: Regression test for incorrect constant propagation
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function foo(s: string)
	{
	if ( s == "foo" )
		s = "bar";
	else if ( s == "bar" )
		s = "bletch";

	print s;
	}

event zeek_init()
	{
	foo("xyz");
	}
