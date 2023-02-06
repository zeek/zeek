# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-canonifier | $SCRIPTS/diff-remove-abspath' btest-diff weird.log

@load base/frameworks/notice/weird

event zeek_init()
	{
	local v = vector("this is a test",
	                 "one two three four one two three four",
	                 "this is a test test test",
	                 "1 2 3 4",
	                 "a b",
	                 "foo",
	                 "1bar2foo3",
	                 ""
	                 );
	local pat = /[a-z]+/;

	for ( i in v )
		print find_all_ordered(v[i], pat);

	# Test input string length limiting.
	local b = find_all_ordered(v[0], pat, 5);
	print b;
	}
