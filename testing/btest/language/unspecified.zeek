# @TEST-DOC: Test representation of unspecified table, set and vector
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

print type_name(set());
print type_name(table());
print type_name(vector());
