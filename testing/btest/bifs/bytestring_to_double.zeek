#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local s1 = "\x43\x26\x4f\xa0\x71\x30\x80\x00"; # 3.14e15
	local s2 = "\xc3\x26\x4f\xa0\x71\x30\x80\x00"; #-3.14e15
	local s3 = "\x00\x1c\xc3\x59\xe0\x67\xa3\x49"; # 4e-308
	local s4 = "\x00\x00\x00\x00\x00\x00\x00\x00"; # 0.0
	local s5 = "\x80\x00\x00\x00\x00\x00\x00\x00"; #-0.0
	local s6 = "\x7f\xf0\x00\x00\x00\x00\x00\x00"; # Inf
	local s7 = "\xff\xf0\x00\x00\x00\x00\x00\x00"; #-Inf
	local s8 = "\x7f\xf8\x00\x00\x00\x00\x00\x00"; # NaN
	local s9 = "\x00\x00\x00\x00\x00\x00\x00\x01"; # subnormal

	print bytestring_to_double(s1);
	print bytestring_to_double(s2);
	print fmt("%e", bytestring_to_double(s3));
	print fmt("%e", bytestring_to_double(s4));
	print fmt("%e", bytestring_to_double(s5));
	print bytestring_to_double(s6);
	print bytestring_to_double(s7);
	print bytestring_to_double(s8);
	print fmt("%.2e", bytestring_to_double(s9));
	}
