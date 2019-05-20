# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	min: count &optional;
	max: count;
};

type FooVector: vector of string;
type FooVectorD: vector of double;
type FooVectorRec: vector of MyRec;

global myvec: FooVector = FooVector("one", "two", "three");
global myvecd: FooVectorD = FooVectorD(1, 2, 3);
global myvecrec: FooVectorRec = FooVectorRec([$max=1], [$max=2], [$max=3]);

print myvec;
print myvecd;
print myvecrec;
