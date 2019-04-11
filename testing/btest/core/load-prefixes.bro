# A test of prefix-based @load'ing

# @TEST-EXEC: bro addprefixes >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE addprefixes.bro
@prefixes += lcl
@prefixes += lcl2
@TEST-END-FILE

# Since base/utils/site.bro is a script, only a script with the original file
# extension can be loaded here.
@TEST-START-FILE lcl.base.utils.site.bro
print "loaded lcl.base.utils.site.bro";
@TEST-END-FILE

@TEST-START-FILE lcl2.base.utils.site.bro
print "loaded lcl2.base.utils.site.bro";
@TEST-END-FILE

# For a script package like base/protocols/http/, either of the recognized
# file extensions can be loaded here.
@TEST-START-FILE lcl.base.protocols.http.zeek
print "loaded lcl.base.protocols.http.zeek";
@TEST-END-FILE

@TEST-START-FILE lcl2.base.protocols.http.bro
print "loaded lcl2.base.protocols.http.bro";
@TEST-END-FILE
