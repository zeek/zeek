# @TEST-DOC: Ensures arithmetic type checking works when adding to vector; regression test for #4722
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type WithCount: record {
	a: count;
};

type WithInt: record {
	a: int;
};

type WithDouble: record {
	a: double;
};

type CountRecVec: vector of WithCount;
global vec_count = CountRecVec([$a=1], [$a=2], [$a=3]);

type IntRecVec: vector of WithInt;
global vec_int = IntRecVec([$a=+1], [$a=+2], [$a=+3]);
global vec_count_int = IntRecVec([$a=1], [$a=2], [$a=3]);

type DoubleRecVec: vector of WithDouble;
global vec_double = DoubleRecVec([$a=1.0], [$a=2.0], [$a=3.0]);
global vec_count_double = DoubleRecVec([$a=1], [$a=2], [$a=3]);
global vec_int_double = DoubleRecVec([$a=+1], [$a=+2], [$a=-3]);

print vec_count;

print vec_int;
print vec_count_int;

print vec_double;
print vec_count_double;
print vec_int_double;
