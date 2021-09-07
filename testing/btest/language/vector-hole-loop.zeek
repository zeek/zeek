# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local v: vector of string;

	v[1] = "foo";
	v[2] = "bar";
	v[4] = "baz";

	print v;

	for ( idx in v )
		print idx;

	for ( idx in v )
		print v[idx];
	}

