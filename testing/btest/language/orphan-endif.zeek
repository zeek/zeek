# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# Check that orphan endif's are detected.

@if ( T )
print "so far, so good";
@endif
@endif
print "whoops!";
