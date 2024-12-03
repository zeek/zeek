# @TEST-DOC: Test Describe() of assert statement. Expressions may be canonicalized.
#
# @TEST-EXEC: zeek -b -O no-event-handler-coalescence %INPUT >out 2>&1
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
