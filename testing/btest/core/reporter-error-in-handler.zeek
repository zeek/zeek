#
# This test produces a recursive error: the error handler is itself broken. Rather
# than looping indefinitely, the error inside the handler should reported to stderr.
#
# @TEST-EXEC: zeek -b %INPUT >output 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

global a: table[count] of count;

global c = 0;

event reporter_error(t: time, msg: string, location: string)
	{
	c += 1;

	if ( c > 1 )
		print "FAILED: 2nd error reported to script as well.";

	else
		{
		print "1st error printed on script level";
		print a[2];
		}
	}

event zeek_init()
	{
	print a[1];
	}
