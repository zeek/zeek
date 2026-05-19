# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a: int = -2;
	print a ?as count;

	local b: int = 2;
	print b as count;

	local c: double = 3.14;
	print c as count;

	local d: double = 3.9;
	print d as count;

	print "7" as count;
	print "" ?as count;
	print "-5" as count;
	# We automatically trim leading, but not trailing whitespace.
	print " 205" as count; # Okay.
	print "206 " as count; # Error.
	print "10101100", 2 as count;
	print "43", 8 as count;
	print "C3", 16 as count;
	print "0xC3", 16 as count;
	print "not a count" ?as count;

	local e: port = 123/tcp;
	print e as count;

	local origString = "9223372036854775808";
	local directCount: count = 9223372036854775808;
	local fromStringCount = origString as count;

	if ( directCount == fromStringCount )
		print fmt("%s and %s are the same", directCount, fromStringCount);
	else
		print fmt("%s and %s are not the same", directCount, fromStringCount);
	}
