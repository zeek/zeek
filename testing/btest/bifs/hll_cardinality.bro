#
# @TEST-EXEC: bro %INPUT>out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local m1 = "measurement1";
	local m2 = "measurement2";

	print "This value should be true:";
	print hll_cardinality_init(0.01, m1);
	hll_cardinality_init(0.01, m2);

	print "This value should be false:";
	print hll_cardinality_init(0.02, "measurement1");

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

	print "This value should be true:";
	print hll_cardinality_add("j", m1);

	print "This value should be false:";
	print hll_cardinality_add("asdf", "something");


	hll_cardinality_add(add1, m2);
	hll_cardinality_add(add2, m2);
	hll_cardinality_add(add3, m2);
	hll_cardinality_add(1, m2);
	hll_cardinality_add("b", m2);
	hll_cardinality_add(2, m2);
	hll_cardinality_add(3, m2);
	hll_cardinality_add(4, m2);
	hll_cardinality_add(5, m2);
	hll_cardinality_add(6, m2);
	hll_cardinality_add(7, m2);
	hll_cardinality_add(8, m2);
	
	print "This value should be around 13:";
	print hll_cardinality_estimate("measurement1");

	print "This value should be -1.0:";
	print hll_cardinality_estimate("m2");

	hll_cardinality_init(0.02, "m2");

	print "This value should be around 0:";
	print hll_cardinality_estimate("m2");

	print "This value should be true:";
	print hll_cardinality_destroy("m2");

	print "This value should be false:";
	print hll_cardinality_destroy("m2");

	print "This value should be -1.0:";
	print hll_cardinality_estimate("m2");

	print "This next thing should be false:";
	print hll_cardinality_clone("m3", "m2");

	print "This next thing should be true:";
	print hll_cardinality_clone("measurement3", "measurement1");

	print "This value should be around 13:";
	print hll_cardinality_estimate("measurement3");

	hll_cardinality_destroy("measurement3");

	print "This next thing should be equal to -1.0:";
	print hll_cardinality_estimate("measurement3");

	print "This value should be around 13:";
	print hll_cardinality_estimate("measurement1");

	print "This value should be true:";
	print hll_cardinality_merge_into("measurement3", "measurement2");

	print "This value should be false:";
	print hll_cardinality_merge_into("measurement4", "measurement6");

	print "This value should be about 12:";
	print hll_cardinality_estimate("measurement3");

	print "This value should be false:";
	print hll_cardinality_merge_into("measurement3", "measurement15");

	print "This value should be about 12:";
	print hll_cardinality_estimate("measurement3");

	print "This value should be true:";
	print hll_cardinality_merge_into("measurement2", "measurement1");

	print "This value should be about 21:";
	print hll_cardinality_estimate("measurement2");

	print "This value should be about 13:";
	print hll_cardinality_estimate("measurement1");

	print "This value should be about 12:";
	print hll_cardinality_estimate("measurement3");

	local keys = hll_cardinality_keys();
	for(key in keys)
		{
		print "The key is:";
		print key;
		print "The value is:";
		print hll_cardinality_estimate(key);
		}
	}

#function hll_cardinality_keys%(%): bool
#	%{
#//	TableVal* a = new TableVal(string_set);
#//	map<BroString, CardinalityCounter*>::iterator it;
#
#//	for(it = hll_counters.begin() ; it != hll_counters.end(); it++)
#//		{
#//		a->Assign((*it).first);
#//		}
#//	return a;
#	return new Val(1, TYPE_BOOL);
