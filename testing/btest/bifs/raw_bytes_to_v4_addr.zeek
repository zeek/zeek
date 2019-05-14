#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print raw_bytes_to_v4_addr("ABCD");
	print raw_bytes_to_v4_addr("ABC");
	}
