# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Invalid on globals
global a: int &optional;

# TODO: Invalid on parameters
function f(a: int &optional)
	{
	# Invalid in locals
	local b: int &optional;
	}
