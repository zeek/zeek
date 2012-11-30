#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "this is another test";
	local b = "is";
	local c = "at";

	print subst_string(a, b, c);
	}
