# This tests the @unload directive
#
# Test that @unload works with ".bro" when there is no ".zeek" script
# @TEST-EXEC: zeek -b unloadbro misc/loaded-scripts dontloadmebro > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep dontloadmebro loaded_scripts.log && exit 1 || exit 0
#
# Test that @unload looks for ".zeek" first (assuming no file extension is
# specified in the @unload)
# @TEST-EXEC: zeek -b unload misc/loaded-scripts dontloadme.zeek dontloadme.bro > output2
# @TEST-EXEC: btest-diff output2
# @TEST-EXEC: grep dontloadme.bro loaded_scripts.log

@TEST-START-FILE unloadbro.bro
@unload dontloadmebro
@TEST-END-FILE

@TEST-START-FILE dontloadmebro.bro
print "Loaded: dontloadmebro.bro";
@TEST-END-FILE

@TEST-START-FILE unload.zeek
@unload dontloadme
@TEST-END-FILE

@TEST-START-FILE dontloadme.zeek
print "Loaded: dontloadme.zeek";
@TEST-END-FILE

@TEST-START-FILE dontloadme.bro
print "Loaded: dontloadme.bro";
@TEST-END-FILE
