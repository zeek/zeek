# This test verifies Zeek's file path normalization.
#
# Absolute paths are preserved but normalized:
# @TEST-EXEC: zeek -b $PWD/././test.zeek 2>&1 | sed "s|$PWD|/...|" >output
#
# Unanchored files become localized ("./test.zeek"):
# @TEST-EXEC: zeek -b test.zeek 2>>output
#
# Redundant path constructs get stripped:
# @TEST-EXEC: zeek -b .//test.zeek 2>>output
# @TEST-EXEC: zeek -b ././test.zeek 2>>output
#
# More complex constructs get normalized too:
# @TEST-EXEC: mkdir foo
# @TEST-EXEC: zeek -b ./foo/../././test.zeek 2>>output
#
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE test.zeek
event idontexist() { }
# @TEST-END-FILE
