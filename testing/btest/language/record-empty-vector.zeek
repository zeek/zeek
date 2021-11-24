# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type r: record {
	v: vector of int;
};

event zeek_init()
	{
	local l = r($v=vector());
	l$v[1] = 9;
	print l$v;
	}
