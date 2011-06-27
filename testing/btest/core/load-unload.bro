# This tests the @unload directive
#
# @TEST-EXEC: echo 'print "oops";' >dontloadmebro.bro
# @TEST-EXEC: bro -l %INPUT dontloadmebro >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

@unload dontloadmebro
