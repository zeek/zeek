#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print to_int("1");
	print to_int("-1");
	print to_int("not an int");
	}
