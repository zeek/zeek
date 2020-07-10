# @TEST-EXEC: zeek -b %INPUT >out 2>&1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global myev: event(a: string, b: string &deprecated="Don't use 'b'", c: string);
global myev: event(a: string, c: string);
global myev: event(a: string, b: string) &deprecated="Don't use this prototype";

event myev(a: string, b: string, c: string) &priority=11
	{
	print "myev (canon)", a, b, c;
	}

event myev(a: string, c: string) &priority = 7
	{
	print "myev (new)", a, c;
	}

event myev(a: string, b: string) &priority = 5
	{
	print "myev (old)", a, b;
	}

event zeek_init()
	{
	event myev("one", "two", "three");
	}

