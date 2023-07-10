# @TEST-DOC: Adapt in v7.1 to check for errors upon GLOBAL accesses.

# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module GLOBAL;

function test_function() { }

global X = 42;


module MyModule;

global X = fmt("shadows ::X (%s)", ::X);

event zeek_init()
	{
	test_function();
	::test_function();
	GLOBAL::test_function();

	print "X", X;
	print "::X", ::X;
	print "GLOBAL::X", GLOBAL::X;
	}
