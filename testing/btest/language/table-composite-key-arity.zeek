# @TEST-DOC: A table constructor whose key arity does not match the declared composite index is rejected when the constructor is type-checked, so the interpreter and the script optimizer agree and unreachable code is diagnosed too.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	local t: table[count, count] of string = { [1] = "a" };
	}

# Too many index expressions, and in code that never runs.
function never_called()
	{
	local u: table[count, count] of string = { [1, 2, 3] = "b" };
	}
