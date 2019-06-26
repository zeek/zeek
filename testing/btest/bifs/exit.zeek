#
# @TEST-EXEC: zeek -b %INPUT >out || test $? -eq 7
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "hello";
	exit(7);
	}
