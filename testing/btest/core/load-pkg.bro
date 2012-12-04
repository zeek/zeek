# @TEST-EXEC: bro -b foo >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE foo/__load__.bro
@load ./test.bro
@TEST-END-FILE

@TEST-START-FILE foo/test.bro
print "Foo loaded";
@TEST-END-FILE
