# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type r: record {
	f: any;
};

type rr: record {
	f: r;
};

type rv: record {
	f: vector of any;
};

type rt: record {
	f: table[count] of any;
};

global a: set[any];
global b: table[any] of count;
global c: set[r];
global d: table[r] of count;
global e: set[rr];
global f: set[rv];
global g: set[rt];
