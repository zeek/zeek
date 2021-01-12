# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local outer = 100;

local lambda = function[outer]()
	{
	local inner = function[outer](a: count, b: count, c: count, d: count, e: count, f: count)
		{
		print outer + f;
		};

	inner(1, 2, 3, 4, 5, 6);
	};

lambda();

local copyLambda = copy(copy(copy(lambda)));
copyLambda();
