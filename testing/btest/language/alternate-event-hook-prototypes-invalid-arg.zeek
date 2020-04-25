# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_event: event(s: string, c: count);
global my_event: event(nope: string, cantdothis: count);

global my_hook: hook(s: string, c: count);
global my_hook: hook(andnotthiseither: addr);

event my_event(s: string, c: count)
	{
	print "my_event", s, c;
	}

hook my_hook(s: string, c: count)
	{
	print "my_hook", s, c;
	}

event zeek_init()
	{
	hook my_hook("infinite", 13);
	event my_event("enantiodromia", 42);
	}
