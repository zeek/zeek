# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type X: record {
     a: list of bool &default=list(T, F, T);
     b: list of bool &default=list();
};

global x: X;

global a: list of count;

a = list();
print a;

a = list(1,2,3);
print a;

print x$a;
print x$b;
