# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global ss: set[string] &default=0;
global d: count &default = 10
		&default = 9
		&optional
		&log
		&add_func = function(): count { return 3; };
global myset: set[count] &default=set();
