# @TEST-DOC: Test behavior of &default when deleting a record field and subsequently accessing it again.
#
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type FooBar: record {
        a: set[string] &default=set();
        b: table[string] of count &default=table();
        c: vector of string &default=vector();
};

global test: FooBar;

delete test$a;
delete test$b;
delete test$c;

print test;

# @TEST-START-NEXT
global c = 99;

# Helper function that's running as part of R's default construction.
function seq(): count {
	++c;
	return c;
}

type R: record {
	c: count &default=seq();
};

type FooBar: record {
        v: vector of count &default=vector(1, 2, 3, seq());
	r: R &default=R();
};

global test: FooBar;
print "default", test;
test$v += 4711;
test$r$c = 42;
print "after changing", test;
delete test$v;
delete test$r;
print "after delete", test;
