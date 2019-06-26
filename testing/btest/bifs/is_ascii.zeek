#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a test\xfe";
	local b = "this is a test\x7f";

	print is_ascii(a);
	print is_ascii(b);
	}
