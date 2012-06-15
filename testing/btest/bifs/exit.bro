#
# @TEST-EXEC: bro %INPUT >out || test $? -eq 7
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print "hello";
	exit(7);
	}
