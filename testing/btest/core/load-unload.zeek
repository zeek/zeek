# This tests the @unload directive
#
# Test that @unload works with ".bro" when there is no ".zeek" script
# @TEST-EXEC: zeek -b unload misc/loaded-scripts dontloadme > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep dontloadme loaded_scripts.log && exit 1 || exit 0

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
z