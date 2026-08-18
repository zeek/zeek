# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

function foo(a: string)
	{ print a; }

function foo(a: string)
	{ }

event zeek_init()
	{ foo("hello"); }
