# @TEST-DOC: Ensures Zeek does not infinitely recurse on function calls
#
# @TEST-EXEC: zeek -b %INPUT >output
#
# Keep the baseline diffs separate for ordering on all platforms
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function recurse(n: count): count
	{
	# Hard limit at 20 (low number so it doesn't take too many resources)
	if ( n >= 20 )
		return 0;

	return 1 + recurse(n + 1);
	}

event zeek_done()
	{
	print fmt("Default max recursion depth: %d", get_max_recursion_depth());
	print recurse(0); # Default should allow 20 nested calls
	set_max_recursion_depth(0);
	print recurse(0); # 0 means no limit
	set_max_recursion_depth(10);
	print recurse(0); # Hits limit
	}
