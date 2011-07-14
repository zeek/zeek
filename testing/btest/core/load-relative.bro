# A test of relative-path-based @load'ing

# @TEST-EXEC: mkdir foo
# @TEST-EXEC: echo "@load ./bar" > foo/foo.bro
# @TEST-EXEC: echo "@load ../baz" >> foo/foo.bro
# @TEST-EXEC: echo 'print "foo loaded";' >> foo/foo.bro
# @TEST-EXEC: echo 'print "bar loaded";' > foo/bar.bro
# @TEST-EXEC: echo 'print "baz loaded";' > baz.bro
# @TEST-EXEC: bro foo/foo >output
# @TEST-EXEC: btest-diff output
