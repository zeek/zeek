#
# @TEST-EXEC: BRO_SEED_FILE= bro %INPUT 2>/dev/null >out
# @TEST-EXEC: BRO_SEED_FILE= bro %INPUT 2>/dev/null >>out
# @TEST-EXEC: cat out | sort | uniq | wc -l | sed 's/ //g' >count
# @TEST-EXEC: btest-diff count

print unique_id("A-");
print unique_id("B-");
print unique_id("C-");
