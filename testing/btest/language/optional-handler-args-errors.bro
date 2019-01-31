# @TEST-EXEC-FAIL: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_event: event(a: count, b: string, c: port);

event my_event(a: string)
	{
	print "wrong param name/type match", a;
	}

event my_event(myb: string)
	{
	print "param renaming requires strict ordering", myb;
	}

event my_event(a: count)
	{
	print "can't access a param not in handler param list", b;
	}

event bro_init()
	{
	event my_event(42, "foobar", 80/tcp);
	}
