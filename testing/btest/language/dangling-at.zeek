# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr
# Check that dangling conditionals are detected.

@if ( 1==1 )
print "it's true!";
@else
lalala
