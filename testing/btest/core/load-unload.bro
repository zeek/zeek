# This tests the @unload directive
#
# @TEST-EXEC: echo 'print "oops12345";' >dontloadmebro.bro
# @TEST-EXEC: bro %INPUT misc/loaded-scripts dontloadmebro > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff loaded_scripts.log

@unload dontloadmebro
