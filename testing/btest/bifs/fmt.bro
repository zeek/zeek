#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

type color: enum { Red, Blue };

event bro_init()
	{
	local a = "foo";
	local b = 3;
	local c = T;
	local d = Blue;
	local e = vector( 1, 2, 3);
	local f = set( 1, 2, 3);
	local g: table[count] of string = { [1] = "test", [2] = "bro" };
	local h = "this\0test";

	#print fmt(c, b, a);   # this should work, according to doc comments

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
	print fmt("*%10s*", d);
	print fmt("*%10s*", e);
	print fmt("*%10s*", f);
	print fmt("*%10s*", g);

	# tests of various data types without field width
	print fmt("%e", 3.1e+2);
	print fmt("%f", 3.1e+2);
	print fmt("%g", 3.1e+2);
	print fmt("%.3e", 3.1e+2);
	print fmt("%.3f", 3.1e+2);
	print fmt("%.3g", 3.1e+2);
	print fmt("%.7g", 3.1e+2);

	# these produce same result
	print fmt("%As", h);
	print fmt("%s", h);

	}
