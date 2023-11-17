# @TEST-DOC: Test the sub() and gsub() functions.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	local a = "this is a test";
	local pat = /is|ss/;

	print sub(a, pat, "at");
	print gsub(a, pat, "at");
	}

event zeek_init() &priority=-1
	{
	local r = sub("test", /^est/, "ea");
	assert r == "test", r;
	print r;

	r = sub("test", /tes$/, "foo");
	assert r == "test", r;
	print r;

	r = sub("test", /test/, "foo");
	assert r == "foo", r;
	print r;

	r = sub("test", /^test$/, "foo");
	assert r == "foo", r;
	print r;

	r = sub("test", /est$/, "ea");
	assert r == "tea", r;
	print r;
	}

event zeek_init() &priority=-2
	{
	local r = gsub("test test", /^test/, "tea");
	assert r == "tea test", r;
	print r;

	r = gsub("test test", /test$/, "tea");
	assert r == "test tea", r;
	print r;

	r = gsub("test test", /test$/, "tea");
	assert r == "test tea", r;
	print r;

	r = gsub("test test", /test/, "tea");
	assert r == "tea tea", r;
	print r;

	r = gsub("test test", /est/, "ea");
	assert r == "tea tea", r;
	print r;

	r = gsub("test test", /^test test$/, "tea");
	assert r == "tea", r;
	print r;
	}
