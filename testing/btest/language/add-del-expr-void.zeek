# @TEST-DOC: checks for type-checking for add/delete expressions
#
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global my_set: set[count];

event zeek_init()
	{
	local my_any1: any = add my_set[3];
	local my_any2: any = delete my_set[5];
	print my_any1, my_any2;
	}
