# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo(s: string)
	{ print fmt("foo(%s: string)", s); }
function foo(c: count)
	{ print fmt("foo(%s: count)", c); }
function foo()
	{ print "foo()"; }

foo(13);
foo("hello");
foo();
