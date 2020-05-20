 #
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


event zeek_init()
	{

	# unsupported byte lengths
	print bytestring_to_count("", T); # 0
	print bytestring_to_count("", F); # 0
	print bytestring_to_count("\xAA\xBB\xCC", T); # 0
	print bytestring_to_count("\xAA\xBB\xCC", F); # 0
	print bytestring_to_count("\xAA\xBB\xCC\xDD\xEE", T); # 0
	print bytestring_to_count("\xAA\xBB\xCC\xDD\xEE", F); # 0

	# 8 bit
	print bytestring_to_count("\xff", T); # 255
	print bytestring_to_count("\xff", F); # 255
	print bytestring_to_count("\x00", T); # 0
	print bytestring_to_count("\x00", F); # 0

	# 16 bit
	print bytestring_to_count("\x03\xe8", F); # 1000
	print bytestring_to_count("\xe8\x03", T); # 1000
	print bytestring_to_count("\x30\x39", F); # 12345
	print bytestring_to_count("\x39\x30", T); # 12345
	print bytestring_to_count("\x00\x00", F); # 0
	print bytestring_to_count("\x00\x00", T); # 0

	# 32 bit
	print bytestring_to_count("\x00\x00\xff\xff", F); # 65535
	print bytestring_to_count("\xff\xff\x00\x00", T); # 65535
	print bytestring_to_count("\xff\xff\xff\xff", F); # 4294967295
	print bytestring_to_count("\xff\xff\xff\xff", T); # 4294967295
	print bytestring_to_count("\x11\x22\x33\x44", F); # 287454020
	print bytestring_to_count("\x11\x22\x33\x44", T); # 1144201745
	print bytestring_to_count("\x00\x00\x00\xff", F); # 255
	print bytestring_to_count("\xff\x00\x00\x00", T); # 255
	print bytestring_to_count("\xAA\xBB\xBB\xAA", F); # 2864429994
	print bytestring_to_count("\xAA\xBB\xBB\xAA", T); # 2864429994
	print bytestring_to_count("\x00\x00\x00\x00", F); # 0
	print bytestring_to_count("\x00\x00\x00\x00", T); # 0

	# 64 bit
	print bytestring_to_count("\xff\xff\xff\xff\xff\xff\xff\xff", F); # 18446744073709551615
	print bytestring_to_count("\xff\xff\xff\xff\xff\xff\xff\xff", T); # 18446744073709551615
	print bytestring_to_count("\xff\xff\xff\x00\x00\xff\xff\xff", F); # 18446742974214701055
	print bytestring_to_count("\xff\xff\xff\x00\x00\xff\xff\xff", T); # 18446742974214701055
	print bytestring_to_count("\x00\x00\x00\x00\x00\x00\xff\xff", F); # 65535
	print bytestring_to_count("\xff\xff\x00\x00\x00\x00\x00\x00", T); # 65535
	print bytestring_to_count("\x00\x00\x00\x00\x00\x00\x00\x00", T); # 0
	print bytestring_to_count("\x00\x00\x00\x00\x00\x00\x00\x00", F); # 0

	# test the default endianness parameter
	print bytestring_to_count("\x00\x00\x00\x00\x00\x00\xff\xff"); # 65535

	}
