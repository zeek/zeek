# @TEST-EXEC: zeek -uu -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type r: record {
	a: count;
	b: count &optional;
	c: count &default = 9;
	d: string &is_set;
	e: string;
};

type r2: record {
	no_worries: r &is_set;
	worries: r;
};

event zeek_init()
	{
	local x: r;
	print x;

	local x2: r2;
	print x2;

	local x3: count;
	print x3;
	}
