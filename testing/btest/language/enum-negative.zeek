# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

type my_enum: enum {
	explicitly_negative = -1,
	overflow = 9223372036854775808,
};
