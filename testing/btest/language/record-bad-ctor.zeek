# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# At least shouldn't crash Zeek, just report the invalid record ctor.

global asdfasdf;
const blah = [$ports=asdfasdf];
const x = blah;

global asdfasdf2: port;
const blah2 = [$ports=asdfasdf2];

print blah, blah2;
