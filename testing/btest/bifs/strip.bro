#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "  this is a test ";
	local b = "";
	local c = " ";

	print fmt("*%s*", a);
	print fmt("*%s*", strip(a));
	print fmt("*%s*", b);
	print fmt("*%s*", strip(b));
	print fmt("*%s*", c);
	print fmt("*%s*", strip(c));
	}
