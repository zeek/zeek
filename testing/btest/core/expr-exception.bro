# Bro shouldn't crash when doing nothing, nor outputting anything.
#
# @TEST-EXEC: cat /dev/null | bro -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff reporter.log

event connection_established(c: connection)
	{
	print c$ftp;
	}
