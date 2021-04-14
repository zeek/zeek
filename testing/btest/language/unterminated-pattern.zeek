# @TEST-DOC: Checks that a useful error message is given for unterminated patterns
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

print /foo
