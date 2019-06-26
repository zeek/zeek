#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print string_to_pattern("foo", F);
	print string_to_pattern("", F);
	print string_to_pattern("b[a-z]+", F);

	print string_to_pattern("foo", T);
	print string_to_pattern("", T);
	print string_to_pattern("b[a-z]+", T);
	}
