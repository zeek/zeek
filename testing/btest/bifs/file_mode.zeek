#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 420;  # octal: 0644
	print file_mode(a);

	a = 511;  # octal: 0777
	print file_mode(a);

	a = 1023;  # octal: 01777
	print file_mode(a);

	a = 1000;  # octal: 01750
	print file_mode(a);

	a = 2541;  # octal: 04755
	print file_mode(a);

	a = 2304;  # octal: 04400
	print file_mode(a);

	a = 1517;  # octal: 02755
	print file_mode(a);

	a = 1312;  # octal: 02440
	print file_mode(a);

	a = 111;  # octal: 0157
	print file_mode(a);

	a = 0;
	print file_mode(a);
	}
