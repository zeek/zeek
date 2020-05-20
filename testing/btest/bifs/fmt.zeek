#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type color: enum { Red, Blue };

event zeek_init()
	{
	local a = Blue;
	local b = vector( 1, 2, 3);
	local c = set( 1, 2, 3);
	local d: table[count] of string = { [1] = "test", [2] = "bro" };

	# tests with only a format string (no additional args)
	print fmt("test");
	print fmt("%%");

	# no arguments 
	print fmt();

	# tests of various data types with field width specified
	print fmt("*%-10s*", "test");
	print fmt("*%10s*", "test");
	print fmt("*%10s*", T);
	print fmt("*%-10s*", T);
	print fmt("*%10.2e*", 3.14159265);
	print fmt("*%-10.2e*", 3.14159265);
	print fmt("*%10.2f*", 3.14159265);
	print fmt("*%10.2g*", 3.14159265);
	print fmt("*%10.2e*", -3.14159265);
	print fmt("*%10.2f*", -3.14159265);
	print fmt("*%10.2g*", -3.14159265);
	print fmt("*%-10.2e*", -3.14159265);
	print fmt("*%-10.2f*", -3.14159265);
	print fmt("*%-10.2g*", -3.14159265);
	print fmt("*%10d*", -128);
	print fmt("*%-10d*", -128);
	print fmt("*%10d*", 128);
	print fmt("*%010d*", 128);
	print fmt("*%-10d*", 128);
	print fmt("*%10x*", 160);
	print fmt("*%010x*", 160);
	print fmt("*%10x*", 160/tcp);
	print fmt("*%10s*", 160/tcp);
	print fmt("*%10s*", 127.0.0.1);
	print fmt("*%10x*", 127.0.0.1);
	print fmt("*%10s*", 192.168.0.0/16);
	print fmt("*%10s*", [::1]);
	print fmt("*%10x*", [fe00::1]);
	print fmt("*%10s*", [fe80:1234::1]);
	print fmt("*%10s*", [fe80:1234::]/32);
	print fmt("*%10s*", 3hr);
	print fmt("*%10s*", /^foo|bar/);
	print fmt("*%10s*", a);
	print fmt("*%10s*", b);
	print fmt("*%10s*", c);
	print fmt("*%10s*", d);

	# tests of various data types without field width
	print fmt("%e", 3.1e+2);
	print fmt("%f", 3.1e+2);
	print fmt("%g", 3.1e+2);
	print fmt("%.3e", 3.1e+2);
	print fmt("%.3f", 3.1e+2);
	print fmt("%.3g", 3.1e+2);
	print fmt("%.7g", 3.1e+2);

	# Tests of "%s" with non-printable characters (the string length is printed
	# instead of the string itself because the print command does its own
	# escaping)
	local s0 = "\x00\x1f";
	local s1 = fmt("%s", s0);
	print |s0|;
	print |s1|;

	s0 = "\x7f\xff";
	s1 = fmt("%s", s0);
	print |s0|;
	print |s1|;
	}
