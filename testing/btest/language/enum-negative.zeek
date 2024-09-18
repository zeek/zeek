# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff output

type my_enum: enum {
	explicitly_negative = -1,
	overflow = 9223372036854775808,
};
