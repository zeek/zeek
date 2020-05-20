#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "abc\xffdefghijklmnopqrstuvwxyz";

	print hexdump(a);
	}
