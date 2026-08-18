# @TEST-DOC: Test representation of unspecified table, set and vector
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff-remove-abspath output

print type_name(set());
print type_name(table());
print type_name(vector());
