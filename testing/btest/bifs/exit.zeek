#
# @TEST-EXEC: bro -b %INPUT >out || test $? -eq 7
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "hello";
	exit(7);
	}
