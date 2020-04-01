# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_event: event(s: string, c: count);

global my_hook: hook(s: string, c: count);

event my_event(s: string, c: count)
	{
	print "my_event", s, c;
	}

event my_event(c: count, s: string)
	{
	print "my_event", c, s;
	}

event my_event(s: string)
	{
	print "my_event", s;
	}

event my_event(c: count)
	{
	print "my_event", c;
	}

event my_event()
	{
	print "my_event";
	}

hook my_hook(s: string, c: count)
	{
	print "my_hook", s, c;
	}

hook my_hook(c: count, s: string)
	{
	print "my_hook", c, s;
	}

hook my_hook(s: string)
	{
	print "my_hook", s;
	}

hook my_hook(c: count)
	{
	print "my_hook", c;
	}

hook my_hook()
	{
	print "my_hook";
	}

event zeek_init()
	{
	hook my_hook("infinite", 13);
	event my_event("enantiodromia", 42);
	}
