#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local s1 = "\x59\x32\x72\x04"; # 3.14e15
	local s2 = "\xd9\x32\x72\x04"; #-3.14e15
	local s3 = "\x01\x59\xc7\xdd"; # 4e-38
	local s4 = "\x00\x00\x00\x00"; # 0.0
	local s5 = "\x80\x00\x00\x00"; #-0.0
	local s6 = "\x7f\x80\x00\x00"; # Inf
	local s7 = "\xff\x80\x00\x00"; #-Inf
	local s8 = "\x7f\xc0\x00\x00"; # NaN
	local s9 = "\x00\x00\x00\x01"; # subnormal

	print bytestring_to_float(s1);
	print bytestring_to_float(s2);
	print fmt("%e", bytestring_to_float(s3));
	print fmt("%e", bytestring_to_float(s4));
	print fmt("%e", bytestring_to_float(s5));
	print bytestring_to_float(s6);
	print bytestring_to_float(s7);
	print bytestring_to_float(s8);
	print fmt("%.2e", bytestring_to_float(s9));

	# Error case, passing an incorrectly-sized string. This returns zero.
	print bytestring_to_float("\x00\x00\x00");
	}
