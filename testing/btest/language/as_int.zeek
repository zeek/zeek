# @TEST-EXEC: zeek -b %INPUT 1>out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "1" as int;
	print "-1" as int;
	print "10111100", 2 as int;
	print "47", 8 as int;
	print "F3", 16 as int;
	print "0xF3", 16 as int;
	print "4294967296" as int;
	print "not an int" ?as int;
	# We automatically trim leading, but not trailing whitespace.
	print " 205" as int; # Okay.
	print "206 " as int; # Error.

	local a: double = 3.14;
	print a as int;

	local b: double = 3.9;
	print b as int;

	local c: double = -3.14;
	print c as int;

	local d: double = -3.9;
	print d as int;
	}
