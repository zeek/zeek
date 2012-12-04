#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

global a = "bro test";

event bro_init()
	{
	local b = "local value";

	print lookup_ID("a");
	print lookup_ID("");
	print lookup_ID("xyz");
	print lookup_ID("b");
	print type_name( lookup_ID("bro_init") );
	}
