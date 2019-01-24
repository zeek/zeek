# @TEST-EXEC-FAIL: bro -b a.bro >output1 2>&1
# @TEST-EXEC-FAIL: bro -b a.bro b.bro >output2 2>&1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff output2

@TEST-START-FILE a.bro
module A;

event bro_init()
	{
	print "a";
@TEST-END-FILE

@TEST-START-FILE b.bro
module B;

event bro_init()
	{
	print "b";
	}
@TEST-END-FILE
