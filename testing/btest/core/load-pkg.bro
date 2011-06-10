# @TEST-EXEC: mkdir foo
# @TEST-EXEC: echo "@load foo/test.bro" >foo/__load__.bro
# @TEST-EXEC: cp %INPUT foo/test.bro
# @TEST-EXEC: bro -l foo >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

print "Foo loaded";
