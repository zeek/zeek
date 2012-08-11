event bro_init()
	{
	local m1 = "measurement1";
	local m2 = "measurement2";

	hll_cardinality_init(0.01, m1);

	local add1 = "hey";
	local add2 = "hi";
	local add3 = 123;

	hll_cardinality_add(add1, m1);
	hll_cardinality_add(add2, m1);
	hll_cardinality_add(add3, m1);
	hll_cardinality_add("a", m1);
	hll_cardinality_add("b", m1);
	hll_cardinality_add("c", m1);
	hll_cardinality_add("d", m1);
	hll_cardinality_add("e", m1);
	hll_cardinality_add("f", m1);
	hll_cardinality_add("g", m1);
	hll_cardinality_add("h", m1);
	hll_cardinality_add("i", m1);
	hll_cardinality_add("j", m1);

	local e = hll_cardinality_estimate(m1);
	print e;

	}
