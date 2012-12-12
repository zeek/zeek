#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print convert_for_pattern("foo");
	print convert_for_pattern("");
	print convert_for_pattern("b[a-z]+");
	}
