# @TEST-DOC: Regression tests for past ZAM bugs inlining empty functions
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function empty_func1() { }
function empty_func2() { local i: int; }
function empty_func3() { local i = 1; }

# Use a global to avoid constant propagation optimizing out the conditional.
global bar = F;

event zeek_init()
	{
	if ( bar )
		empty_func1();
	else
		empty_func1();

	print "got through the conditional #1";

	if ( bar )
		empty_func2();
	else
		empty_func2();

	print "got through the conditional #2";

	if ( bar )
		empty_func3();
	else
		empty_func3();

	print "got through the conditional #3";
	}
