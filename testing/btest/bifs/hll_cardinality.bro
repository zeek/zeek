#
# @TEST-EXEC: bro %INPUT>out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local c1 = hll_cardinality_init(0.01);
	local c2 = hll_cardinality_init(0.01);

	local add1 = "hey";
	local add2 = "hi";
	local add3 = 123;

	hll_cardinality_add(c1, add1);
	hll_cardinality_add(c1, add2);
	hll_cardinality_add(c1, add3);
	hll_cardinality_add(c1, "a");
	hll_cardinality_add(c1, "b");
	hll_cardinality_add(c1, "c");
	hll_cardinality_add(c1, "d");
	hll_cardinality_add(c1, "e");
	hll_cardinality_add(c1, "f");
	hll_cardinality_add(c1, "g");
	hll_cardinality_add(c1, "h");
	hll_cardinality_add(c1, "i");
	hll_cardinality_add(c1, "j");

	hll_cardinality_add(c2, add1);
	hll_cardinality_add(c2, add2);
	hll_cardinality_add(c2, add3);
	hll_cardinality_add(c2, 1);
	hll_cardinality_add(c2, "b");
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

	local m2 = hll_cardinality_init(0.02);

	print "This value should be around 0:";
	print hll_cardinality_estimate(m2);

	local c3 = hll_cardinality_clone(c1);

	print "This value should be around 13:";
	print hll_cardinality_estimate(c3);

	c3 = hll_cardinality_init(0.01);
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

