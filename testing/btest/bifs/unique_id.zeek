#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
print unique_id_from(4, "D-");
print unique_id_from(5, "E-");
print unique_id_from(5, "F-");
