#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print to_int("1");
	print to_int("-1");
	print to_int("4294967296");
	print to_int("not an int");
	}
