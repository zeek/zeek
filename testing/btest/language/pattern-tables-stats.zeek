# @TEST-DOC: Test table_pattern_matcher_stats()
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global pt: table[pattern] of count;
global ps: set[pattern];

function matcher_stats(tbl: any): string
	{
	local stats = table_pattern_matcher_stats(tbl);
	return fmt("[matchers=%d, patterns=%d, stream_matchers=%d, cache_bytes=%d, cache_clears=%d]",
	           stats$matchers, stats$patterns, stats$stream_matchers, stats$cache_bytes,
	           stats$cache_clears);
	}

event zeek_init()
	{
	print "initial stats", matcher_stats(pt);
	pt[/foo/] = 1;
	print "populated stats", matcher_stats(pt);

	print pt["foo"], pt["foox"], "foo" in pt, "foox" in pt;
	print "after lookup stats", matcher_stats(pt);

	pt[/bar/] = 2;
	pt[/(foo|bletch)/] = 3;
	print "reset stats", matcher_stats(pt);

	print pt["x"], pt["bletch"], sort(pt["foo"]), "foo" in pt, "x" in pt;
	print "after more lookup stats", matcher_stats(pt);

	delete pt[/bar/];
	print "reset stats after delete", matcher_stats(pt);

	print pt["x"], pt["bletch"], sort(pt["foo"]);
	print "after even more lookup stats", matcher_stats(pt);

	pt = table();
	print "reset after reassignment", matcher_stats(pt);
	}

event zeek_init() &priority=-10
	{
	print "set initial stats", matcher_stats(ps);
	add ps[/foo/];
	print "set populated stats", matcher_stats(ps);

	print "foo" in ps, "foox" in ps;
	print "set after lookup stats", matcher_stats(ps);

	add ps[/bar/];
	add ps[/(foo|bletch)/];
	print "set reset stats", matcher_stats(ps);

	print "x" in ps, "bletch" in ps;
	print "set after more lookup stats", matcher_stats(ps);

	delete ps[/bar/];
	print "set reset stats after delete", matcher_stats(ps);

	ps = set();
	print "set reset after reassignment", matcher_stats(ps);
	}
