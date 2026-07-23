# @TEST-DOC: An assignment used as a value inside a constructor is reported as an error instead of aborting the script optimizer.
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1 || true
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global g: count;

event zeek_init()
	{
	local t = table([1] = (g = 5));
	}
