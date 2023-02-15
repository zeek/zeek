# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MyRecord: record {
	s1: string;
};

redef MyRecord += {
	s2: string;
};


# @TEST-START-NEXT
type Color: enum {
	RED,
	GREEN,
};

redef Color += {
	BLUE,
};

# @TEST-START-NEXT
type Color: enum {
	RED,
	GREEN,
};

# This is very bogus.
redef Color: enum += {
	BLUE,
};

# @TEST-START-NEXT
# ...more bogus things.
redef count += { 1 };

# @TEST-START-NEXT
# ...more bogus things.
redef string_set += { &log };

# @TEST-START-NEXT
# ...also bogus.
type sv: vector of string;
redef sv += { 1 };
