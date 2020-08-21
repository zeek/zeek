# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event myev(t: table[string] of count)
	{ }

hook myhk(t: table[string] of count)
	{ }

global foo = 3;

global t: table[string] of count &expire_func=myev;
global tt: table[string] of count &expire_func=myhk;
global ttt: table[string] of count &expire_func=foo;
