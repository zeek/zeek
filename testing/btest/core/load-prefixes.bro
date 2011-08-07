# A test of prefix-based @load'ing

# @TEST-EXEC: bro addprefixes >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE addprefixes.bro
@prefixes += lcl
@prefixes += lcl2
@TEST-END-FILE

@TEST-START-FILE lcl.base.utils.site.bro
print "loaded lcl.base.site.bro";
@TEST-END-FILE

@TEST-START-FILE lcl2.base.utils.site.bro
print "loaded lcl2.base.site.bro";
@TEST-END-FILE

@TEST-START-FILE lcl.base.protocols.http.bro
print "loaded lcl.base.protocols.http.bro";
@TEST-END-FILE

@TEST-START-FILE lcl2.base.protocols.http.bro
print "loaded lcl2.base.protocols.http.bro";
@TEST-END-FILE
