# Expressions in an event handler that raise interpreter exceptions
# shouldn't abort Bro entirely, but just return from the function body.
#
# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff reporter.log
# @TEST-EXEC: btest-diff output

event connection_established(c: connection)
	{
	print c$ftp;
	print "not reached";
	}

event connection_established(c: connection)
	{
	if ( c?$ftp )
		print c$ftp;
	else
		print "ftp field missing";
	}

event connection_established(c: connection)
	{
	print c$id;
	}
