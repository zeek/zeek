#
# Test the quality of HLL once by checking adding a large number of IP entries.
#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: BRO_SEED_FILE="" zeek -b %INPUT > out2
# @TEST-EXEC: head -n1 out2 >> out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local cp: opaque of cardinality = hll_cardinality_init(0.1, 1.0);
	local base: count = 2130706432; # 127.0.0.0
	local i: count = 0;
	while ( ++i < 170000 )
		{
		hll_cardinality_add(cp, count_to_v4_addr(base+i));
		}

	local res: int = double_to_count(hll_cardinality_estimate(cp));
	if ( |res - 170000| > 17000 )
		print "Big error";
	else
		print "Ok error";

	print hll_cardinality_estimate(cp);
	}
