# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global pt: table[pattern] of count;

event zeek_init()
	{
	# test_case("indexing empty", |pt["foo"] == 0|);
	print "indexing empty", |pt["foo"]|;

	pt[/foo/] = 1;

	print "single insert, match", pt["foo"];
	print "single insert, non-match", pt["foox"];
	print "single insert, in", "foo" in pt;
	print "single insert, not-in", "foox" in pt;

	pt[/bar/] = 2;
	pt[/(foo|bletch)/] = 3;

	print "multiple inserts, non-match", pt["x"];
	print "multiple inserts, single match", pt["bletch"];
	print "multiple inserts, double match", sort(pt["foo"]);
	print "multiple insert, in", "foo" in pt;
	print "multiple insert, not-in", "x" in pt;

	pt[/(foo|bletch|xyz)/] = 4;
	print "triple match", sort(pt["foo"]);

	pt[/dog.*cat/] = 5;
	pt[/dog.*cat/s] = 6;
	pt[/dog.*cat/i] = 7;
	print "embedded newline, /s operator", pt["dog\ncat"];
	print "no embedded newline, /s vs. no /s operator", sort(pt["dogmousecat"]);
	print "no embedded newline, case sensitive, /i vs. no /i operator", sort(pt["dogmouseCat"]);

	delete pt[/(foo|bletch)/];
	print "single delete, no more triple match", pt["foo"];

	delete pt[/bar/];
	delete pt[/foo/];
	print "double delete, no more double match", pt["foo"];

	delete pt[/nosuchpattern/];
	print "delete of non-existing pattern", pt["foo"];

	local copy_pt = pt;
	print "shallow copy matches multi", sort(pt["dogmousecat"]);

	local deep_copy_pt = copy(pt);
	print "deep copy matches multi", sort(pt["dogmousecat"]);

	clear_table(pt);
	print "delete of entire table", pt["foo"];

	local replacement_pt: table[pattern] of count;
	deep_copy_pt = replacement_pt;
	print "reassignment of table", deep_copy_pt["dogmousecat"];
	}
