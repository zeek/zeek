#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print convert_for_pattern("foo");
	print convert_for_pattern("");
	print convert_for_pattern("b[a-z]+");
	}
