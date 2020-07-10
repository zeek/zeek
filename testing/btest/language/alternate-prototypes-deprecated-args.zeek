# @TEST-EXEC: zeek -b %INPUT >out 2>&1
#
# @TEST-EXEC-FAIL: zeek -b %INPUT hide.zeek >hidden-error 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff hidden-error

global myev: event(a: string, b: string &deprecated="Don't use 'b'", c: string);
global myev: event(a: string, c: string);
global myev: event(a: string, b: string) &deprecated="Don't use this prototype";

event myev(a: string, b: string, c: string) &priority=11
	{
	print "myev (canon)", a, b, c;
	}

event myev(a: string, c: string) &priority = 7
	{
	local ddd = vector(1,2,3);
	print "myev (new)", a, c, ddd;
	}

global eee = vector(1,2,3);

event myev(a: string, c: string) &priority = 6
	{
	for ( o in eee )
		print "myev (new)", a, c, o;
	}

event myev(a: string, b: string) &priority = 5
	{
	print "myev (old)", a, b;
	}

event zeek_init()
	{
	event myev("one", "two", "three");
	}

@TEST-START-FILE hide.zeek
event myev(a: string, c: string) &priority = 7
	{
	local ddd = vector(1,2,3);
	print "myev (new)", a, c, ddd;
	print b;
	}
@TEST-END-FILE
