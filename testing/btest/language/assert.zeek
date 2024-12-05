# @TEST-DOC: Assert statement behavior testing without an assertion_failure() hook.
#
# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b -O no-event-handler-coalescence %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	assert fmt("%s", 1) == "2";
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert fmt("%s", 1) == "2", fmt("\"%s\" != \"2\"", 1);
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert to_count("42") == 42.5, "always failing";
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	local x = 2;
	assert x == 1, fmt("Expected x to be 1, have %s", x);
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	local tbl: table[string] of string = [
		["abc"] = "123",
		["def"] = "456",
	];
	assert "abc" in tbl, cat(tbl);
	assert "def" in tbl, cat(tbl);
	assert "ghi" in tbl, cat(tbl);
	}

@TEST-START-NEXT
type MyRecord: record {
	a: count;
	b: count &optional;
};

event zeek_init()
	{
	local r: MyRecord = [$a=1234];
	assert ! r?$b, fmt("Unexpected r$b is set to %s", r$b);
	assert r?$b, fmt("r$b is not set in %s", r);
	}

@TEST-START-NEXT
type MyRecord: record {
	a: count;
	b: count &optional;
};

event zeek_init()
	{
	local r: MyRecord = [$a=1234];
	assert ! r?$b, fmt("Unexpected r$b is set to %s", r$b);
	# This will generate a run-time error, rather than reporting the
	# failed assertion.
	assert r?$b, fmt("r$b is not set trying anyway: %s", r$b);
	}

@TEST-START-NEXT
assert 1 == 1, "always true";
assert 1 == 2, "always false";
print "not reached";
