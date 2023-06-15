# @TEST-DOC: Test Describe() of assert statement. Expressions may be canonicalized.
#
# Doesn't make sense for ZAM as it ignores assert's.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function test_function()
	{
	assert getpid() > 0;
	}

event zeek_init()
	{
	local f = function() {
		assert getpid() > 0, fmt("my pid is funny: %s", getpid());
	};
	local g = function() {
		assert to_count("42") == 42;
	};

	print "f", f;
	f();

	print "g", g;
	g();

	print "test_function", test_function;
	test_function();
	}
