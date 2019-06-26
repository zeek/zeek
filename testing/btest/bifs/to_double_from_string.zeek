# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff error

function test_to_double(d: string, expect: double)
	{
	local result = to_double(d);
	print fmt("to_double(%s) = %s (%s)", d, result,
	          result == expect ? "SUCCESS" : "FAILURE");
	}

test_to_double("3.14", 3.14);
test_to_double("-3.14", -3.14);
test_to_double("0", 0);
test_to_double("NotADouble", 0);
test_to_double("", 0);
