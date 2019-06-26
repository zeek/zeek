#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = vector( F, T, F );
	print any_set(a);

	local b: vector of bool = vector();
	print any_set(b);

	local c = vector( F );
	print any_set(c);
	}
