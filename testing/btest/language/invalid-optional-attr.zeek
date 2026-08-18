# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

# Invalid on globals
global a: int &optional;

# Invalid on parameters
function f(a: int &optional)
	{
	# Invalid in locals
	local b: int &optional;
	}
