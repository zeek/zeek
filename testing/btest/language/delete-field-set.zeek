# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type FooBar: record {
        a: set[string] &default=set();
        b: table[string] of count &default=table();
        c: vector of string &default=vector();
};

global test: FooBar;

print test?$a, test?$b, test?$c;

delete test$a;
delete test$b;
delete test$c;

print test?$a, test?$b, test?$c;
print test;
print test?$a, test?$b, test?$c;
