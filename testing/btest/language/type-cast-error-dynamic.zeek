# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record  {
    a: addr;
    b: port;
};

function cast_to_string(a: any)
	{
	print a as string;
	}

event zeek_init()
	{
	cast_to_string(42);
	}

event zeek_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];
	cast_to_string(x);
	}

event zeek_init()
	{
	print "data is string", Broker::Data() is string;
	cast_to_string(Broker::Data());
	}


