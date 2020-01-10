# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local outer = 100;

	local lambda = function()
		{
		# If inner lambdas are being traversed for outer IDs, a will be detected.
		local inner = function(a: count, b: count, c: count, d: count, e: count, f: count)
			{
			local innerInner = function()
				{
				print outer + f;
				};

			innerInner();
			};

		inner(1, 2, 3, 4, 5, 6);
		};

	lambda();
	local copyLambda = copy(copy(copy(copy(copy(lambda)))));
	copyLambda();
	}
