# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

local i_min = -9223372036854775808;
local i_min_p1 = -9223372036854775807;

# These should be caught at parse-time as outside the range of a 64-bit ints.
local i_min_m1 = -9223372036854775809;
local i_min_m2 = -9223372036854775810;
