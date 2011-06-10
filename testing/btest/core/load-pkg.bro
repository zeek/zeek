# @TEST-EXEC: mkdir foo
# @TEST-EXEC: echo "@load foo/test.bro" >foo/__load__.bro
# @TEST-EXEC: cp %INPUT foo/test.bro
# @TEST-EXEC: bro foo >output
# @TEST-EXEC: btest-diff output

print "Foo loaded";
