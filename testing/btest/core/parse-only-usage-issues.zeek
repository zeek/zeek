# Skip this test when using ZAM, as it will generate a hard error in addition
# to the warning.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-DOC: ``zeek -a -u`` should detect usage issues without executing code
# @TEST-EXEC: zeek -b -a -u %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	local a: count;
	local b: count;

	if ( a > 3 )
		b = 5;

	print a, b;
	}
