# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-EXEC: ZEEK_USAGE_ISSUES=2 zeek -b %INPUT >out 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

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

	local x3: r2 &is_assigned;
	print x3;

	local x4: count;
	# note, no execution after this point due to error

	# We use this slightly baroque expression because compiled code
	# may have x4 genuinely uninitialized, and we want deterministic
	# output in that case.
	if ( x4 > 5 )
		print T;
	else
		print T;
	}
