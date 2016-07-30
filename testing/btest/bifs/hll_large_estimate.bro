#
# Test the quality of HLL once by checking adding a large number of IP entries.
#
# @TEST-EXEC: bro %INPUT > out
# @TEST-EXEC: BRO_SEED_FILE="" bro %INPUT > out2
# @TEST-EXEC: head -n1 out2 >> out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local cp: opaque of cardinality = hll_cardinality_init(0.1, 0.99);
	local base: count = 2130706432; # 127.0.0.0
	local i: count = 0;
	while ( ++i < 170000 )
		{
		hll_cardinality_add(cp, count_to_v4_addr(base+i));
		}

	local res: int = double_to_count(hll_cardinality_estimate(cp));
	if ( |res - 170000| > 15000 )
		print "Big error";
	else
		print "Ok error";

	print hll_cardinality_estimate(cp);
	}
