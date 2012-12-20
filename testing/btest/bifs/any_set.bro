#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = vector( F, T, F );
	print any_set(a);

	local b = vector();
	print any_set(b);

	local c = vector( F );
	print any_set(c);
	}
