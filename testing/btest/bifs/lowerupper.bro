#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "this is a Test";

	print to_lower(a);
	print to_upper(a);
	}
