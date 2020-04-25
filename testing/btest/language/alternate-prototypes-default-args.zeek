# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC-FAIL: zeek -b bad.zeek >errors 2>&1
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff errors

global foo: event(a: string, b: string, c: string &default="C");
global foo: event(c: string, b: string, a: string);
global foo: event(a: string);
global foo: event(b: string);
global foo: event(c: string);

event foo(a: string, b: string, c: string)
	{
	print "foo", a, b, c;
	}

event foo(mya: string, b: string, c: string)
	{
	print "foo", mya, b, c;
	}

event foo(c: string, b: string, a: string)
	{
	print "reverse foo", a, b, c;
	}

event foo(a: string)
	{
	print "foo a", a;
	}

event foo(b: string)
	{
	print "foo b", b;
	}

event foo(c: string)
	{
	print "foo c", c;
	}

event zeek_init()
	{
	event foo("A", "B");
	}

@TEST-START-FILE bad.zeek
global foo: event(a: string, b: string, c: string &default="C");
global foo: event(c: string, b: string, a: string &default="A");
@TEST-END-FILE bad.zeek
