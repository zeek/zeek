# @TEST-DOC: Regression test for past ZAM issues with inlining empty functions in conditionals
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function empty_func() {}

# Use a global to avoid constant propagation optimizing out the conditional.
global bar = F;

event zeek_init()
	{
	if ( bar )
		empty_func();
	else
		empty_func();

	print "got through the conditional";
	}
