# @TEST-DOC: Checks that a useful error message is given for unterminated patterns
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

print /foo
