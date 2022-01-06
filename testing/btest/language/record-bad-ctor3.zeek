# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Every element in a record ctor's expression list should have an assignment
# form.  Make sure we correctly report errors when that's not the case.

global a = 3;

type r: record { x: count; y: count; };

event zeek_init()
	{
	local b: r = record($x = a + 5, a + 9);
	print b;
	}
