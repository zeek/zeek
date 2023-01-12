# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

type test: record {
	a: count;
	a: string &optional;
};

type r1: record {
	a: count;
	b: count;
};

type r2: record {
	a: count;
	a: count;
};

type r3: record {
	b: count;
	a: count;
	a: count;
};

type r4: record {
	a: count;
	b: count;
	a: count;
	b: count;
	a: count;
	c: count;
};

global x1: r1;
global x2: r2;
global x3: r3;
global x4: r4;

event zeek_init()
	{
	local a = test($a=5);
	print a;
	print x1, x2, x3, x4;
	}
