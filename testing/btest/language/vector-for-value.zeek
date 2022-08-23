# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local vec: vector of string = { "zero", "one", "two" };
vec[4] = "four";

for ( i, v in vec )
	{
	print i, v;
	}

for ( [i], v in vec )
	{
	print i, v;
	}

for ( _, v in vec )
	{
	print v;
	}
