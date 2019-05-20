#
# @TEST-EXEC: zeek %INPUT>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event zeek_init()
	{
	local c1 = hll_cardinality_init(0.01, 0.95);
	local c2 = hll_cardinality_init(0.01, 0.95);

	local add1 = 2001;
	local add2 = 2002;
	local add3 = 2003;

	hll_cardinality_add(c1, add1);
	hll_cardinality_add(c1, add2);
	hll_cardinality_add(c1, add3);
	hll_cardinality_add(c1, 1000);
	hll_cardinality_add(c1, 1001);
	hll_cardinality_add(c1, 101);
	hll_cardinality_add(c1, 1003);
	hll_cardinality_add(c1, 1004);
	hll_cardinality_add(c1, 1005);
	hll_cardinality_add(c1, 1006);
	hll_cardinality_add(c1, 1007);
	hll_cardinality_add(c1, 1008);
	hll_cardinality_add(c1, 1009);

	hll_cardinality_add(c2, add1);
	hll_cardinality_add(c2, add2);
	hll_cardinality_add(c2, add3);
	hll_cardinality_add(c2, 1);
	hll_cardinality_add(c2, "b");
	hll_cardinality_add(c2, 101);
	hll_cardinality_add(c2, 2);
	hll_cardinality_add(c2, 3);
	hll_cardinality_add(c2, 4);
	hll_cardinality_add(c2, 5);
	hll_cardinality_add(c2, 6);
	hll_cardinality_add(c2, 7);
	hll_cardinality_add(c2, 8);

	print "This value should be around 13:";
	print hll_cardinality_estimate(c1);

	print "This value should be about 12:";
	print hll_cardinality_estimate(c2);

	local m2 = hll_cardinality_init(0.02, 0.95);

	print "This value should be around 0:";
	print hll_cardinality_estimate(m2);

	local c3 = hll_cardinality_copy(c1);

	print "This value should be around 13:";
	print hll_cardinality_estimate(c3);

	c3 = hll_cardinality_init(0.01, 0.95);
	print "This value should be 0:";
	print hll_cardinality_estimate(c3);

	print "This value should be true:";
	print hll_cardinality_merge_into(c3, c2);

	print "This value should be about 12:";
	print hll_cardinality_estimate(c2);
	print hll_cardinality_estimate(c3);

	print "This value should be true:";
	print hll_cardinality_merge_into(c2, c1);

	print "This value should be about 21:";
	print hll_cardinality_estimate(c2);

	print "This value should be about 13:";
	print hll_cardinality_estimate(c1);

	print "This value should be about 12:";
	print hll_cardinality_estimate(c3);

	}

