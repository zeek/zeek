# @TEST-EXEC-FAIL: bro -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record  {
    a: addr;
    b: port;
};

event bro_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];

	print "string" as count;
	print "string" as X;
	}


