# @TEST-EXEC-FAIL: zeek -b a.zeek >output1 2>&1
# @TEST-EXEC-FAIL: zeek -b a.zeek b.zeek >output2 2>&1
# @TEST-EXEC: btest-diff output1
# @TEST-EXEC: btest-diff output2

@TEST-START-FILE a.zeek
module A;

event zeek_init()
	{
	print "a";
@TEST-END-FILE

@TEST-START-FILE b.zeek
module B;

event zeek_init()
	{
	print "b";
	}
@TEST-END-FILE
