#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print bytestring_to_hexstr("04");
	print bytestring_to_hexstr("");
	print bytestring_to_hexstr("\0");
	}
