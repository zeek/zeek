# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function foo(a: string)
	{ print a; }

function foo(a: string)
	{ }

event zeek_init()
	{ foo("hello"); }
