# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-canonifier | $SCRIPTS/diff-remove-abspath' btest-diff weird.log

@load base/frameworks/notice/weird

event zeek_init()
	{
	local a = "this is a test";
	local pat = /hi|es/;
	local pat2 = /aa|bb/;

	local b = find_all(a, pat);
	local b2 = find_all(a, pat2);

	for (i in b)
		print i;
	print "-------------------";
	print |b2|;

	# Test input string length limiting.
	local b3 = find_all(a, pat, 5);
	print |b3|;
	}
