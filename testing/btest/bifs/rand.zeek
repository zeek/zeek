#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: zeek -b %INPUT do_seed=F >out.2
# @TEST-EXEC: unset ZEEK_SEED_FILE && zeek -b %INPUT real_random=T >out.3
# @TEST-EXEC: for i in $(seq 21); do echo 0 >>random-zero.seed; done
# @TEST-EXEC: ZEEK_SEED_FILE=random-zero.seed zeek -b %INPUT >out.4
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out.2
# @TEST-EXEC: btest-diff out.3
# @TEST-EXEC: btest-diff out.4

const do_seed = T &redef;
const real_random = F &redef;

event zeek_init()
	{
	if ( real_random )
		return;

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

event zeek_init() &priority=-10
	{
	if ( ! real_random )
		return;

	local v1: vector of count = vector();
	local v2: vector of count = vector();
	local i = 0;

	while ( i < 20 )
		{
		v1 += rand(65535);
		i += 1;
		}

	i = 0;

	while ( i < 20 )
		{
		v2 += rand(65535);
		i += 1;
		}

	# Note: this is expected to be F with high probability, but
	# technically could all be the same because, well, that's a
	# valid "random" sequence, too
	print all_set(v1 == v2);

	if ( all_set(v1 == v2) )
		{
		print v1;
		print v2;
		}
	}
