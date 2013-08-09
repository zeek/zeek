#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print raw_bytes_to_v4_addr("ABCD");
	print raw_bytes_to_v4_addr("ABC");
	}
