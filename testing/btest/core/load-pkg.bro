# @TEST-EXEC: mkdir foo
# @TEST-EXEC: echo "@load foo/test.bro" >foo/__load__.bro
# @TEST-EXEC: cp %INPUT foo/test.bro
# @TEST-EXEC: bro misc/loaded-scripts foo >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff loaded_scripts.log

print "Foo loaded";
