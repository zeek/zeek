#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print bytestring_to_hexstr("04");
	print bytestring_to_hexstr("");
	print bytestring_to_hexstr("\0");
	}
