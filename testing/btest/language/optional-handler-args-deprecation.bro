# @TEST-EXEC: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_event: event(a: count, b: string &deprecated, c: port);

event my_event(a: count, b: string, c: port)
	{
	print "my_event", a, b, c;
	}

event my_event(a: count, c: port)
	{
	print "my_event", a, c;
	}

event bro_init()
	{
	event my_event(42, "foobar", 80/tcp);
	}
