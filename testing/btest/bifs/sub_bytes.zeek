# @TEST-DOC: Test the sub_bytes() function.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# These tests are to ensure that script optimization gets all the permutations
# correct, for varying combinations of constant and variable arguments.

global s = "abcdefghij";
global a = 2;
global b = 4;

print sub_bytes(s, a, b);
print sub_bytes(s, 2, b);
print sub_bytes(s, a, 4);
print sub_bytes(s, 2, 4);

print sub_bytes("abcdefghij", a, b);
print sub_bytes("abcdefghij", 2, b);
print sub_bytes("abcdefghij", a, 4);
print sub_bytes("abcdefghij", 2, 4);
