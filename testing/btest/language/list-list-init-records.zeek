# Initializing a list with a list of records should promote elements as
# necessary to match the list's yield type.

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record {
	s: string;
	o: string &optional;
};

const l: list of Foo = {
	[$s="bar", $o="check"],
	[$s="baz"]
};

for ( i in l )
	print fmt("element: %s", i);

print l;
