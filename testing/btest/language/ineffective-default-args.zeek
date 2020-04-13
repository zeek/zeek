# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global grault: event(a: string, b: string &default="B");

global foo: event(a: string, b: string, c: string &default="C");
global foo: event(c: string);

event grault(a: string, b: string &default="G")
	{
	print "grault", a, b;
	}

event corge(c: string &default="C")
	{
	print "corge", c;
	}

event foo(c: string &default="CCCC")
	{
	print "foo c", c;
	}

global bar: function(a: string, b: string);

function bar(a: string &default="A", b: string &default="B")
	{
	print "bar", a, b;
	}

global baz: function(a: string &default="A", b: string &default="B");

function baz(a: string, b: string)
	{
	print "baz", a, b;
	}

global qux: function(a: string &default="A", b: string &default="B");

function qux(a: string &default="Q", b: string &default="Q")
	{
	print "qux", a, b;
	}

event zeek_init()
	{
	bar();
	baz();
	qux();
	event grault("A");
	event corge();
	event foo("A", "B");
	}

