# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo(s: string)
	{ print fmt("foo(%s: string)", s); }
function foo(c: count)
	{ print fmt("foo(%s: count)", c); }
function foo()
	{ print "foo()"; }

function indirect_any(): any
	{ return foo; }

local fa: function() = indirect_any();
fa();
local fac: function(c: count) = indirect_any();
fac(43);
local fas: function(s: string) = indirect_any();
fas("cool");

# TODO: currently we don't catch the error at assignment time: from an `any`
# to a non-existent function overload type.  We do find out at run-time that
# there isn't an available overload, but maybe can do better?
# local fan: function(p: port) = indirect_any();
# fan(123/udp);
