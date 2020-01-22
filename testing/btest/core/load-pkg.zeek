# Test that package cannot be loaded when no package loader script exists.
# @TEST-EXEC-FAIL: zeek -b foo

@TEST-START-FILE foo/test.zeek
print "test.zeek loaded";
@TEST-END-FILE
