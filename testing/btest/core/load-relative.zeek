# A test of relative-path-based @load'ing

# @TEST-EXEC: zeek -b foo/foo >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE foo/foo.zeek
@load ./bar
@load ../baz
print "foo loaded";
@TEST-END-FILE

@TEST-START-FILE foo/bar.zeek
print "bar loaded";
@TEST-END-FILE

@TEST-START-FILE baz.zeek
print "baz loaded";
@TEST-END-FILE
