# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: zeek -b one.zeek > output1
# @TEST-EXEC-FAIL: zeek -b two.zeek > output2
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# the first test writes out the sqlite files...

@TEST-START-FILE one.zeek

module TestModule;

global t: table[string] of string &backend=Broker::SQLITE;

event zeek_init()
	{
	t["a"] = "a";
	t["b"] = "b";
	t["c"] = "c";
	print t;
	}

@TEST-END-FILE
@TEST-START-FILE two.zeek

# the second one reads them in again. Or not because the types are incompatible.

module TestModule;

global t: table[count] of count &backend=Broker::SQLITE;


event zeek_init()
	{
	print t;
	}
@TEST-END-FILE
