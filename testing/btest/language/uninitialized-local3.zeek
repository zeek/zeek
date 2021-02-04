# @TEST-EXEC: zeek -uu -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type r: record {
	a: count;
	b: count &optional;
	c: count &default = 9;
	d: string &is_assigned;
	e: string;
};

type r2: record {
	no_worries: r &is_assigned;
	worries: r;
};

event zeek_init()
	{
	local x: r;
	print x;

	if ( x?$a )
		x$e = "I'm set";
	print x;	# should complain about $e, but not about $a

	local x2: r2;
	print x2;

	local x3: count;
	print x3;
	}
