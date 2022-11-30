# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

global count_max: count = 0xffffffffffffffff;

event zeek_init()
{
	local c1 = 0;
	--c1;
	print fmt("local c1 = 0; --c1; c1 == %s; %s", c1, c1 == count_max);

	local c2 = 0;
	c2 -= 1;
	print fmt("local c2 = 0; c2 -= 1; c2 == %s; %s", c2, c2 == count_max);

	local c3 = 0;
	c3 = c3 - 1;
	print fmt("local c3 = 0; c3 = c3 - 1; c3 == %s; %s", c3, c3 == count_max);

	# This also triggers a warning now;
	print "1 - 2", 1 - 2;

	# The following ones all overflow back to 0, but do not log a warning.
	local c4 = count_max;
	++c4;
	print fmt("local c4 = count_max; ++c4; c4 == %s; %s", c4, c4 == 0);

	local c5 = count_max;
	c5 += 1;
	print fmt("local c5 = count_max; c5 += 1; c5 == %s; %s", c5, c5 == 0);

	local c6 = count_max;
	c6 = c6 + 1;
	print fmt("local c6 = count_max; c6 = c6 + 1; c6 == %s; %s", c6, c6 == 0);
}
