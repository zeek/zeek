# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

type test: record {
	a: count;
	a: string &optional;
};

event zeek_init()
	{
	local a = test($a=5);
	print a;
	}
