# TODO: interpreter exceptions currently may cause memory leaks, so disable leak checks
# @TEST-EXEC: ASAN_OPTIONS="$ASAN_OPTIONS,detect_leaks=0" zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff reporter.log

redef Reporter::warnings_to_stderr = F;
redef Reporter::errors_to_stderr = F;

global test: table[count] of string = {};

event my_event()
	{
	print test[3];
	}

event zeek_init()
	{
	# Errors within zeek_init are always printed to stderr, so check whether
	# an error that happens later is suppressed.
	schedule 0.2sec { my_event() };
	}
