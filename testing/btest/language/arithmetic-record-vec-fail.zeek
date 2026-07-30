# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: btest-diff-remove-abspath err

type WithCount: record {
	a: count;
};

type WithInt: record {
	a: int;
};

type CountRecVec: vector of WithCount;
global vec_count_fail = CountRecVec([$a=+1], [$a=-2], [$a=3.0]);

type IntRecVec: vector of WithInt;
global vec_int_fail = IntRecVec([$a=1.0], [$a=+2.0], [$a=-3.0]);
