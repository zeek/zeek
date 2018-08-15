# @TEST-EXEC: bro -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record  {
    a: addr;
    b: port;
};

function cast_to_string(a: any)
	{
	print a as string;
	}

event bro_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];

	cast_to_string(42);
	cast_to_string(x);
	cast_to_string(Broker::Data());
	print "data is string", Broker::Data() is string;
	}


