# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type X: record {
     a: table[string] of bool &default=table( ["foo"] = T );
     b: table[string] of bool &default=table();
     c: set[string] &default=set("A", "B", "C");
     d: set[string] &default=set();
};

global x: X;
global y: table[string] of bool &default=T;

print x$a;
print x$b;
print x$c;
print x$d;

