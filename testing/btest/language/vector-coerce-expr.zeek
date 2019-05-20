# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type X: record {
     a: vector of bool &default=vector(T, F, T);
     b: vector of bool &default=vector();
};

global x: X;

global a: vector of count;

a = vector();
print a;

a = vector(1,2,3);
print a;

print x$a;
print x$b;
