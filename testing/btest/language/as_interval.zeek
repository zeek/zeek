#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 1234563.140 as interval;
	print type_name(a), a;
	local b = (-1234563.14) as interval;
	print type_name(b), b;
	local c = 6.0 as interval;
	print type_name(c), c;

	print "foo" ?as interval;
	}
