# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr
# Check that orphan endif's are detected.

@if ( T )
print "so far, so good";
@endif
@endif
print "whoops!";
