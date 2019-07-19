# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo(s: string)
	{ print fmt("foo(%s: string)", s); }
function foo(c: count)
	{ print fmt("foo(%s: count)", c); }
function foo()
	{ print "foo()"; }

function indirect(): function()
	{ return foo; }
function indirect_count(): function(c: count)
	{ return foo; }
function indirect_string(): function(s: string)
	{ return foo; }

indirect_count()(42);
indirect_string()("hey");
indirect()();
