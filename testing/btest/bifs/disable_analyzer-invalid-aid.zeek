# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-canonifier | $SCRIPTS/diff-remove-abspath' btest-diff out
# @TEST-DOC: Validates that one can use disable_analyzer even for analyzers without parent. This is a regression test for #3071.

event new_connection(c: connection)
	{
	# Iterate over a range of analyzer IDs. This range should include e.g.,
	# `TCP` which has no parent analyzer.
	local i = 0;
	while ( i < 200 )
		{
		disable_analyzer(c$id, i, F, T);
		++i;
		}
	}
