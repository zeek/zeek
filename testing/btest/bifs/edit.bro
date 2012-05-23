#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "hello there";

	print edit(a, "e");
	}
