# @TEST-DOC: Regression test for past ZAM issues with vector-of-any.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

global d: table[string] of vector of double &default=vector();

function crank_one(key: string)
	{
	local c = d[key];
	c += |c|;
	print c;
	if ( |c| > 3 )
		c = c[1:];
	d[key] = c;
	}

event zeek_init()
	{
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	crank_one("foo");
	}
