#
# @TEST-EXEC: BRO_SEED_FILE= zeek -b %INPUT >out
# @TEST-EXEC: BRO_SEED_FILE= zeek -b %INPUT >>out
# @TEST-EXEC: cat out | sort | uniq | wc -l | sed 's/ //g' >count
# @TEST-EXEC: btest-diff count

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
print unique_id_from(4, "D-");
print unique_id_from(5, "E-");
print unique_id_from(5, "F-");
