# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type B: record {
	x: any &optional;
	};

type A: record  {
        x: any &optional;
        y: B;
	};

event zeek_init()
	{
	local x: A;
	x$x = x;
	x$y$x = x;
	local y = copy(x);

	print fmt("%s (expected: F)", same_object(x, y));
	print fmt("%s (expected: T)", same_object(y, y$x));
	print fmt("%s (expected: T)", same_object(y, y$y$x));
	}
