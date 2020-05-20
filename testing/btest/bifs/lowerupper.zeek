#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a Test";

	print to_lower(a);
	print to_upper(a);
	}
