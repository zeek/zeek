# @TEST-DOC: Ensures returning without a value does not segfault.
#
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

function bad_cmp(a: count, b: count): int
	{
	# This space was intentionally left blank :)
	}

event zeek_init()
	{
	local v = vector(3, 1, 2);
	print sort(v, bad_cmp); # This won't sort anything, but it shouldn't segfault, too
	}
