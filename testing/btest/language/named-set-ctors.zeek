# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	min: count &optional;
	max: count;
};

type FooSet: set[count];
type FooSetRec: set[MyRec];
type FooSetComp: set[string, count];

global myset: FooSet = FooSet(1, 5, 3);
global mysetrec: FooSetRec = FooSetRec([$max=5], [$max=2]);
global mysetcomp: FooSetComp = FooSetComp(["test", 1], ["cool", 2]);

print myset;
print mysetrec;
print mysetcomp;
