#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: zeek -b %INPUT do_seed=F >out.2
# @TEST-EXEC: for i in $(seq 21); do echo 0 >>random-zero.seed; done
# @TEST-EXEC: ZEEK_SEED_FILE=random-zero.seed zeek -b %INPUT >out.4
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out.2
# @TEST-EXEC: btest-diff out.4

const do_seed = T &redef;

event zeek_init()
	{
	local a = rand(1000);
	local b = rand(1000);
	local c = rand(1000);

	print a;
	print b;
	print c;

	if ( do_seed )
		srand(575);

	local d = rand(1000);
	local e = rand(1000);
	local f = rand(1000);

	print d;
	print e;
	print f;

	local i = 0;
	local max = 3;

	while ( i < 100 )
		{
		local rn = rand(max);

		if ( rn >= max )
			print fmt("ERROR: rand returned value greater than %s: %s",
			          max, rn);

		i += 1;
		}
	}
