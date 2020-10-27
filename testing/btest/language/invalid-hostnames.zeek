# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

print0.0000000000005;

# @TEST-START-NEXT

# This is not a floating-point literal (like you'd see in C/C++) and it's
# also not a valid hostname since the TLD does not start with a letter.
print 0.05f;
