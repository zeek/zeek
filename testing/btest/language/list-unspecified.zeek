# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# Test assignment behavior of unspecified lists.  A mirror of a similar
# test for vectors.
local a = list();

a += 5;
a += "Hi";
a += 127.0.0.1;

print a;
