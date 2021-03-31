# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

global foo: vector of count = { 42 };
global foo2: table[count] of count = { [0] = 13 };

event zeek_init()
	{
	print "foo[0]", foo[0];
	print "foo[1]", foo[1];
	}

event zeek_init()
	{
	print "foo2[0]", foo2[0];
	print "foo2[1]", foo2[1];
	}

event zeek_done()
	{
	print "done";
	}
