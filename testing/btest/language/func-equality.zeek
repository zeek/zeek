# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo()
	{ print "foo"; }

function bar()
	{ print "bar"; }

global baz = bar;

event zeek_init()
	{
	print foo == bar;
	print foo != bar;
	print bar == baz;
	print bar != baz;
	}
