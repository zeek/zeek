# A test of prefix-based @load'ing

# Can't use this test for -O gen-C++ because none of the scripts has
# testing/btest in its path when loaded, so don't get recognized for
# compilation.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -b base/utils/site base/protocols/http addprefixes >output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE addprefixes.zeek
@prefixes += lcl
@prefixes += lcl2
# @TEST-END-FILE

# Since base/utils/site.zeek is a script, only a script with the original file
# extension can be loaded here.
# @TEST-START-FILE lcl.base.utils.site.zeek
print "loaded lcl.base.utils.site.zeek";
# @TEST-END-FILE

# @TEST-START-FILE lcl2.base.utils.site.zeek
print "loaded lcl2.base.utils.site.zeek";
# @TEST-END-FILE

# For a script package like base/protocols/http/, verify the package can be loaded.
# @TEST-START-FILE lcl.base.protocols.http.zeek
print "loaded lcl.base.protocols.http.zeek";
# @TEST-END-FILE
