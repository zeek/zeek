# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# Test assignment behavior of unspecified vectors.  This used to treat
# "a" as a vector-of-any, but that seems dangerous - if the user really
# wants that behavior, they can explicitly type it as such.
local a = vector();

a[0] = 5;
a[1] = "Hi";
a[2] = 127.0.0.1;

print a;
