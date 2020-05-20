# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record  {
    a: addr;
    b: port;
};

function check(a: any)
	{
	print a, a is string, a is count, a is X;
	}

event zeek_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];

	check("Foo");
	check(1);
	check(x);
	}


