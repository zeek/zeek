# This tests the @unload directive
#
# @TEST-EXEC: echo 'print "oops12345";' >dontloadmebro.bro
# @TEST-EXEC: bro -l %INPUT dontloadmebro >output
# @TEST-EXEC: btest-diff output

@unload dontloadmebro
