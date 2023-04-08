# @TEST-DOC: Test that ListVal::Eval() does not end-up leaking memory by exercising IndexExpr and comparing memory before/after a long running loop. This test is sensitive to the sanitizers. It fails with ASAN enabled even after the fix that motivated the test, so we skip running there.
# @TEST-REQUIRES: ! grep -E 'ZEEK_SANITIZERS:STRING=.+$' ${BUILD}/CMakeCache.txt >&2
# @TEST-EXEC: zeek -b %INPUT >&2

event zeek_done()
	{
	local ctbl: table[count] of count;
	local stbl: table[string] of string;
	local tbl: table[string, count, string, addr, string] of set[string, count];
	local s0 = "s0";
	local c0 = 42;
	local s1 = "s1";
	local a0 = 127.0.0.1;
	local s2 = "s2";
	local c1 = 43;

	local i = 0;

	# Priming
	ctbl[c0] = c0;
	ctbl[c1] = c1;
	stbl[s0] = s0;
	stbl[s1] = s1;
	tbl[s0, c0, s1, a0, s2] = set([s0, c0]);
	tbl[s2, c0, s0, a0, s1] = tbl[s0, c0, s1, a0, s2];
	if ( [s0, c0, s1, a0, s2] !in tbl )
		exit(1);
	if ( [s2, c0, s0, a0, s1] !in tbl )
		exit(1);

	# This loop caused ~16MB of memory growth after c1215ca47 while none
	# is expected. Below is a poor man's approach to capturing the
	# increase via get_proc_stats(). It may cause false negatives, but
	# if something is really off, it probably captures that.
	local start_stats = get_proc_stats();
	while (++i < 50000 )
		{
		ctbl[c0] = c0;
		ctbl[c1] = c1;
		stbl[s0] = s0;
		stbl[s1] = s1;
		tbl[s0, c0, s1, a0, s2] = tbl[s2, c0, s0, a0, s1];
		tbl[s2, c0, s0, a0, s1] = tbl[s0, c0, s1, a0, s2];
		if ( [s0, c0, s1, a0, s2] !in tbl )
			exit(1);
		if ( [s2, c0, s0, a0, s1] !in tbl )
			exit(1);
		}
	local end_stats = get_proc_stats();

	local mb_diff = (end_stats$mem - start_stats$mem) / (1024.0 * 1024.0);
	if ( mb_diff > 0.1 )
		{
		print "start_stats", start_stats;
		print "end_stats", start_stats;
		print fmt("MEMORY GROWTH %.3f MB", mb_diff);
		exit(1);
		}

	# Output in case it's interesting.
	print "start_stats", start_stats;
	print "end_stats", start_stats;
	print "mb_diff", mb_diff;
	}
