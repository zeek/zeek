# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

# Make sure composit types in records are initialized.

type Foo: record {
	a: set[count];
	b: table[count] of string;
	c: vector of string;
};

global f: Foo;

print f;
