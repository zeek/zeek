#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print raw_bytes_to_v6_addr("ABCDEFGHIKLMNOPQ");
	print raw_bytes_to_v6_addr("ABCDEFGHIKLMNOP");
        print raw_bytes_to_v6_addr("\xda\xda\xbe\xef\x00\x00\x00\x00N^\x0c\xff\xfej\x86q");
	}
