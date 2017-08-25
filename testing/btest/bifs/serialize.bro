# @TEST-EXEC: bro -b %INPUT >output
# @TEST_EXEC: btest-diff output

print unserialize(serialize("it works"));
