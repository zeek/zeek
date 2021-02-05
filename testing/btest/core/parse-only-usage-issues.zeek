# @TEST-DOC: ``zeek -a -u`` should detect usage issues without executing code
# @TEST-EXEC: zeek -b -a -u %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	local a: count;
	print a;
	}
