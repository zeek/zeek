# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type MyRec: record {
	b: count;
	c: count;
	d: count &optional;
};

const testtable: table[string] of MyRec = table() &redef;

redef testtable += {
	["one"] = [$b=1, $c=2]
};

redef testtable += {
	["two"] = [$b=1, $c=2, $d=3]
};

redef testtable += {
	["three"] = [1, 2]
};

redef testtable += {
	["four"] = [$b="No."]
};
