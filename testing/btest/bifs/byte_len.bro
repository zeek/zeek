#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "hello\0there";

	print byte_len(a);
	}
