# Initializing a vector with a list of records should promote elements as
# necessary to match the vector's yield type.

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record {
	s: string;
	o: string &optional;
};

const v: vector of Foo = {
	[$s="bar", $o="check"],
	[$s="baz"]
};

for ( i in v )
	print fmt("element %d = %s", i, v[i]);

print v;
