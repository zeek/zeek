#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a test";
	local b = "his";
	local c = "are";

	print strstr(a, b);
	print strstr(a, c);
	}
