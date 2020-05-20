#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a: int = -2;
	print int_to_count(a);

	local b: int = 2;
	print int_to_count(b);

	local c: double = 3.14;
	print double_to_count(c);

	local d: double = 3.9;
	print double_to_count(d);

	print to_count("7");
	print to_count("");
	print to_count("-5");
	print to_count("not a count");

	local e: port = 123/tcp;
	print port_to_count(e);

	local origString =        "9223372036854775808";
	local directCount: count = 9223372036854775808;
	local fromStringCount: count = to_count(origString);

	if ( directCount == fromStringCount )
	   print fmt("%s and %s are the same", directCount, fromStringCount);
	else
	   print fmt("%s and %s are not the same", directCount, fromStringCount);
	}
