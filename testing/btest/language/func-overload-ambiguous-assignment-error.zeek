# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function foo()
	{ print "foo"; }
function foo(s: string)
	{ print "foo string", s; }
function foo(c: count)
	{ print "foo count", c; }

global qux: function(s: string);
global qux: function(c: count);
global qux: function();

event zeek_init() &priority=10
	{
	# This is ambiguous
	qux = foo;
	}

event zeek_init()
	{
	foo();
	foo("adsf");
	foo(1234);
	qux();
	qux("boo");
	qux(55);
	}
