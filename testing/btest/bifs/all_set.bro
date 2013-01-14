#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = vector( T, F, T );
	print all_set(a);

	local b = vector();
	print all_set(b);

	local c = vector( T );
	print all_set(c);
	}
