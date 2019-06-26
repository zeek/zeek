#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "Test \0string";

	print |a|;
	print a;

	local b = clean(a);
	print |b|;
	print b;

	local c = to_string_literal(a);
	print |c|;
	print c;

	local d = escape_string(a);
	print |d|;
	print d;

	local e = string_to_ascii_hex(a);
	print |e|;
	print e;
	}
