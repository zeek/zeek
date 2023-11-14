# @TEST-DOC: set[pattern] also supports parallel RE matching using in expression

# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global ps: set[pattern];

event zeek_init()
	{
	assert "foo" !in ps;
	print "in empty", "foo" in ps;

	add ps[/foo/];

	assert "foo" in ps;
	assert "foox" !in ps;
	print "single insert, foo in", "foo" in ps;
	print "single insert, foox not-in", "foox" !in ps;

	add ps[/bar/];
	add ps[/(foo|bletch)/];

	assert "x" !in ps;
	assert "bar" in ps;
	assert "foo" in ps;
	assert "bletch" in ps;
	assert "foobletch" !in ps;

	print "multiple inserts, x not-in", "x" !in ps;
	print "multiple insert, foo in", "foo" in ps;
	print "multiple insert, bletch in", "bletch" in ps;
	print "multiple insert, foobletch not-in", "foobletch" !in ps;

	# After delete of /foo/, still matches "foo" due to /(foo|bletch)/
	delete ps[/foo/];
	assert "foo" in ps;
	assert "bletch" in ps;
	print "single delete, bletch in", "bletch" in ps;
	print "single delete, foo in", "foo" in ps;

	delete ps[/(foo|bletch)/];
	assert "foo" !in ps;
	assert "bar" in ps;
	assert "bletch" !in ps;
	print "two deletes, bletch not-in", "bletch" !in ps;
	print "two deletes, foo not-in", "foo" !in ps;
	print "two deletes, bar in", "bar" in ps;

	clear_table(ps);
	assert "bar" !in ps;
	print "clear_table, bar not-in", "bar" !in ps;
	}
