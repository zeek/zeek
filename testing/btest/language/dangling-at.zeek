# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# Check that dangling conditionals are detected.

@if ( 1==1 )
print "it's true!";
@else
lalala
