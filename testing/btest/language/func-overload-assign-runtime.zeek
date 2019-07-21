# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo()
	{ print "foo"; }
function foo(s: string)
	{ print "foo string", s; }
function foo(c: count)
	{ print "foo count", c; }

global qux: function(s: string);
global qux: function(c: count) = foo;
global qux: function();

function bar()
	{ print "bar"; }

function qux_string(): function(s: string)
	{ return qux; }
function qux_count(): function(c: count)
	{ return qux; }
function qux_(): function()
	{ return qux; }

event zeek_init() &priority=10
	{
	qux = bar;
	}

function qux(s: string)
	{ print "qux string", s; }
# function qux(c: count)
# 	{ print "qux count", c; }
function qux()
	{ print "qux"; }

event zeek_init()
	{
	qux();
	qux("boo");
	qux(55);

	qux_()();
	qux_string()("blah");
	qux_count()(77);
	}
