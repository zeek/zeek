# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global bar: function(s: string);

function bar(c: count)
	{ print "bar count", c; }

function indirect_no_impl_yet(): function(s: string)
	{ return bar; }

function bar(s: string)
	{ print "bar string", s; }

indirect_no_impl_yet()("testing");
