# @TEST-EXEC-FAIL: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

global c: string;
type t: addr;

event zeek_init()
	{
	local a = 3;
	local b = "hi there";

	local f1 = function[a]() { print "no a!"; };
	local f2 = function[a2](a2: addr) { print a2; };
	local f3 = function[a]() { print b; };
	local f4 = function[a, b]() { print b; };
	local f5 = function[b, b]() { print b; };
	local f6 = function() { print c; };	# should be okay
	local f7 = function[c]() { print c; };
	local f8 = function[t]() { local t2: t; };
	local f9 = function[a]() { local a = 4; };	# error due to shadowing
	}
