# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo(s: string)
	{ print fmt("foo(%s: string)", s); }
function foo(c: count)
	{ print fmt("foo(%s: count)", c); }
function foo()
	{ print "foo()"; }

function use_a_func(f: function(c: count))
	{ f(37); }

local indirect_typed_count: function(c: count) = foo;
indirect_typed_count(808);
local indirect_typed_string: function(s: string) = foo;
indirect_typed_string("wow");
local indirect_typed: function() = foo;
indirect_typed();

use_a_func(foo);
