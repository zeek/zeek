# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Named record constructors should include values for every non-optional,
# non-aggregate field.

type info1 : record {
	str: string;
	cnt: count &optional;
	a: addr &optional;

	v: vector of bool;
	r: record { x: count; };
	s: set[bool];
	t: table[bool] of string;
};

type info2 : record {
	str: string;
	cnt: count;
	a: addr;
};

event zeek_init()
	{
	local resp1 = info1($str="hello");
	print resp1;

	local resp2 = info2($str="hello");
	print resp2;
	}
