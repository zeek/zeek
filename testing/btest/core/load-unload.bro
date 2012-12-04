# This tests the @unload directive
#
# @TEST-EXEC: bro -b %INPUT misc/loaded-scripts dontloadmebro > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep -q dontloadmebro loaded_scripts.log && exit 1 || exit 0

@unload dontloadmebro

@TEST-START-FILE dontloadmebro.bro
print "FAIL";
@TEST-END-FILE
