# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# Record constructors should work in table initializers

type r: record  {
	a: string;
	b: count;
};  

global a: r = [$a="foo", $b=1];
global b: r = [$a="foo", $b=2];
global c: r = [$a="bar", $b=3];
global d: r = [$a="bar", $b=4];
global e: r = [$a="baz", $b=5];
global f: r = [$a="baz", $b=6];

global foo: table[r] of count = {
	[a] = 1,
	[record($a="foo", $b=2)] = 2,
	[[$a="bar", $b=3]] = 3,
};

foo[d] = 4;
foo[[$a="baz", $b=5]] = 5;
foo[record($a="baz", $b=6)] = 6;

print "following should all be true...";

print a in foo;
print b in foo;
print c in foo;
print d in foo;
print e in foo;
print f in foo;

print [$a="foo", $b=1] in foo;
print record($a="foo", $b=1) in foo;

print foo[a];
print foo[[$a="foo", $b=1]];
print foo[record($a="foo", $b=1)];

print "following should all be false...";

local bah: r = [$a="bah", $b=0];

print bah in foo;
print [$a="bah", $b=0] in foo;
print record($a="bah", $b=0) in foo;

print "now here's the foo table...";

print foo;

# @TEST-START-NEXT

# They can be part of a compound index type, too...

type r: record  {
	a: string;
	b: count;
};

global a: r = [$a="foo", $b=1];
global b: r = [$a="foo", $b=2];
global c: r = [$a="bar", $b=3];
global d: r = [$a="bar", $b=4];
global e: r = [$a="baz", $b=5];
global f: r = [$a="baz", $b=6];

global foo: table[r, count] of count = {
	[a, 1] = 1,
	[record($a="foo", $b=2), 2] = 2,
	[[$a="bar", $b=3], 3] = 3,
};

foo[d, 4] = 4;
foo[[$a="baz", $b=5], 5] = 5;
foo[record($a="baz", $b=6), 6] = 6;

print "following should all be true...";

print [a, 1] in foo;
print [b, 2] in foo;
print [c, 3] in foo;
print [d, 4] in foo;
print [e, 5] in foo;
print [f, 6] in foo;

print [[$a="foo", $b=1], 1] in foo;
print [record($a="foo", $b=1), 1] in foo;

print foo[a, 1];
print foo[[$a="foo", $b=1], 1];
print foo[record($a="foo", $b=1), 1];

print "following should all be false...";

local bah: r = [$a="bah", $b=0];

print [bah, 0] in foo;
print [[$a="bah", $b=0], 0] in foo;
print [record($a="bah", $b=0), 0] in foo;

print "now here's the foo table...";

print foo;

# @TEST-START-NEXT

# Now checking table() ctor versus { } initializer

type r: record  {
	a: string;
	b: count;
};  

global a: r = [$a="foo", $b=1];
global b: r = [$a="foo", $b=2];
global c: r = [$a="bar", $b=3];
global d: r = [$a="bar", $b=4];
global e: r = [$a="baz", $b=5];
global f: r = [$a="baz", $b=6];

global foo: table[r] of count = table(
	[a] = 1,
	[record($a="foo", $b=2)] = 2,
	[[$a="bar", $b=3]] = 3
);

foo[d] = 4;
foo[[$a="baz", $b=5]] = 5;
foo[record($a="baz", $b=6)] = 6;

print "following should all be true...";

print a in foo;
print b in foo;
print c in foo;
print d in foo;
print e in foo;
print f in foo;

print [$a="foo", $b=1] in foo;
print record($a="foo", $b=1) in foo;

print foo[a];
print foo[[$a="foo", $b=1]];
print foo[record($a="foo", $b=1)];

print "following should all be false...";

local bah: r = [$a="bah", $b=0];

print bah in foo;
print [$a="bah", $b=0] in foo;
print record($a="bah", $b=0) in foo;

print "now here's the foo table...";

print foo;

# @TEST-START-NEXT

# Now checking table() ctor versus { } initializer for compound index

type r: record  {
	a: string;
	b: count;
};

global a: r = [$a="foo", $b=1];
global b: r = [$a="foo", $b=2];
global c: r = [$a="bar", $b=3];
global d: r = [$a="bar", $b=4];
global e: r = [$a="baz", $b=5];
global f: r = [$a="baz", $b=6];

global foo: table[r, count] of count = table(
	[a, 1] = 1,
	[record($a="foo", $b=2), 2] = 2,
	[[$a="bar", $b=3], 3] = 3
);

foo[d, 4] = 4;
foo[[$a="baz", $b=5], 5] = 5;
foo[record($a="baz", $b=6), 6] = 6;

print "following should all be true...";

print [a, 1] in foo;
print [b, 2] in foo;
print [c, 3] in foo;
print [d, 4] in foo;
print [e, 5] in foo;
print [f, 6] in foo;

print [[$a="foo", $b=1], 1] in foo;
print [record($a="foo", $b=1), 1] in foo;

print foo[a, 1];
print foo[[$a="foo", $b=1], 1];
print foo[record($a="foo", $b=1), 1];

print "following should all be false...";

local bah: r = [$a="bah", $b=0];

print [bah, 0] in foo;
print [[$a="bah", $b=0], 0] in foo;
print [record($a="bah", $b=0), 0] in foo;

print "now here's the foo table...";

print foo;
