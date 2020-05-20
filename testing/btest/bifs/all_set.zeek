#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = vector( T, F, T );
	print all_set(a);

	local b: vector of bool = vector();
	print all_set(b);

	local c = vector( T );
	print all_set(c);
	}
