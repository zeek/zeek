# A test of relative-path-based @load'ing

# @TEST-EXEC: bro -b foo/foo >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE foo/foo.bro
@load ./bar
@load ../baz
print "foo loaded";
@TEST-END-FILE

@TEST-START-FILE foo/bar.bro
print "bar loaded";
@TEST-END-FILE

@TEST-START-FILE baz.bro
print "baz loaded";
@TEST-END-FILE
