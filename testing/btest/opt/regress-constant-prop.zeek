# @TEST-DOC: Regression tests for incorrect constant propagation
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function issue1(s: string)
	{
	if ( s == "foo" )
		s = "bar";
	else if ( s == "bar" )
		s = "bletch";

	print s;
	}

function issue2(i: int)
	{
	local c: count;
	if ( i >= 0 )
		{
		c = i;
		++c;
		print c;
		}
	}

event zeek_init()
	{
	issue1("xyz");
	issue2(-3);
	print "I made it to the end";
	}
