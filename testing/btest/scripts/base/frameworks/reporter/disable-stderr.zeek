# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff reporter.log

redef Reporter::warnings_to_stderr = F;
redef Reporter::errors_to_stderr = F;

global test: table[count] of string = {};

event zeek_init()
	{
	print test[3];
	}
