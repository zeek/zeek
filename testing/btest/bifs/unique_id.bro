#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
print unique_id_from("alpha", "D-");
print unique_id_from("beta", "E-");
print unique_id_from("beta", "F-");
