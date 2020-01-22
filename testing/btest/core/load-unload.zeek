# This tests the @unload directive
#
# @TEST-EXEC: zeek -b unload misc/loaded-scripts dontloadme.zeek > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep -v dontloadme.bro loaded_scripts.log

@TEST-START-FILE unload.zeek
@unload dontloadme
@TEST-END-FILE

@TEST-START-FILE dontloadme.zeek
print "Loaded: dontloadme.zeek";
@TEST-END-FILE
