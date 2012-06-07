#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "abc\xffdefghijklmnopqrstuvwxyz";

	print hexdump(a);
	}
