# Test that package loading works when a package loader script is present.
#
# Test that ".zeek" is loaded when there is also a ".bro"
# @TEST-EXEC: zeek -b foo >output
# @TEST-EXEC: btest-diff output
#
# Test that ".bro" is loaded when there is no ".zeek"
# @TEST-EXEC: rm foo/__load__.zeek
# @TEST-EXEC: zeek -b foo >output2
# @TEST-EXEC: btest-diff output2
#
# Test that package cannot be loaded when no package loader script exists.
# @TEST-EXEC: rm foo/__load__.bro
# @TEST-EXEC-FAIL: zeek -b foo

@TEST-START-FILE foo/__load__.bro
@load ./test
print "__load__.bro loaded";
@TEST-END-FILE

@TEST-START-FILE foo/__load__.zeek
@load ./test
print "__load__.zeek loaded";
@TEST-END-FILE

@TEST-START-FILE foo/test.zeek
print "test.zeek loaded";
@TEST-END-FILE
