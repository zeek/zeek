# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global qux: function(s: string);
global qux: function(c: count);
global qux: function();

# qux isn't defined yet, but these should still end up resolving them fine.
function qux_string(): function(s: string)
	{ return qux; }
function qux_count(): function(c: count)
	{ return qux; }
function qux_(): function()
	{ return qux; }

# Overload definitions can come in a different order than declarations.
function qux(c: count)
	{ print "qux count", c; }
function qux()
	{ print "qux"; }
function qux(s: string)
	{ print "qux string", s; }

qux();
qux("boo");
qux(55);

qux_()();
qux_string()("blah");
qux_count()(77);
