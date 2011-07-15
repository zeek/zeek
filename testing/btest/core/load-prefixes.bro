# A test of prefix-based @load'ing

# @TEST-EXEC: bro addprefixes site protocols/http >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE addprefixes.bro
@prefixes += lcl
@prefixes += lcl2
@TEST-END-FILE

@TEST-START-FILE lcl.site.bro
print "loaded lcl.site.bro";
@TEST-END-FILE

@TEST-START-FILE lcl2.site.bro
print "loaded lcl2.site.bro";
@TEST-END-FILE

@TEST-START-FILE lcl.protocols.http.bro
print "loaded lcl.protocols.http.bro";
@TEST-END-FILE

@TEST-START-FILE lcl2.protocols.http.bro
print "loaded lcl2.protocols.http.bro";
@TEST-END-FILE
