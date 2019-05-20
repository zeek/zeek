#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is another test";
	local b = "is";
	local c = "at";

	print subst_string(a, b, c);
	}
