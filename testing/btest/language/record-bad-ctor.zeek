# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# At least shouldn't crash Bro, just report the invalid record ctor.

global asdfasdf;
const blah = [$ports=asdfasdf];
print blah;
