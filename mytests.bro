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
	}

### The data structure at index1 will contain the combined count for the
## elements measured by index1 and index2.
## It returns true if it either cloned the value at index2 into index1
## or if it merged the two data structures together.

#function hll_cardinality_merge_into%(index1: any, index2: any%): bool
#	%{
#	BroString* s1 = convert_index_to_string(index1);
#	BroString* s2 = convert_index_to_string(index2);
#	int status = 0;
#
#	if(hll_counters.count(*s1) < 1)
#		{
#		if(hll_counters.count(*s2) < 1)
#			{
#			status = 0;
#			}
#		else
#			{
#			uint64_t m = (*hll_counters[*s2]).getM();
#			double error = 1.04/sqrt(m);
#			CardinalityCounter* newInst = new CardinalityCounter(error);
#			int i = 0;
#			while((*newInst).getM() != m)
#				{
#				i += 1;
#				newInst = new CardinalityCounter(error/i);
#				}
#			hll_counters[*s1] = newInst;
#			(*newInst).merge(hll_counters[*s2]);
#			status = 1;
#			}
#		}
#	else
#		{
#		if(hll_counters.count(*s2) < 1)
#			{
#			status = 0;
#			}
#		else
#			{
#			if((*hll_counters[*s2]).getM() == (*hll_counters[*s1]).getM())
#				{
#				status = 1;
##				(*hll_counters[*s1]).merge(hll_counters[*s2]);
##				}
#			}
#		}
#
#	delete s1;
#	delete s2;
#	return new Val(status, TYPE_BOOL);
#
#	%}

##I'm really not sure about the notation of this function...
#
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
#	%}

## Stores the data structure at index2 into index1. Deletes the data structure at index1
## if there was any. Returns True if the data structure at index1 was changed in any way.

#function hll_cardinality_clone%(index1: any, index2: any%): bool
#	%{
#	BroString* s1 = convert_index_to_string(index1);
#	BroString* s2 = convert_index_to_string(index2);
#	int status = 0;
#
#	if(hll_counters.count(*s2) < 1)
#		{
#		if(hll_counters.count(*s1) < 1)
##			{
#			status = 0;
#			}
#		else
#			{
#			delete hll_counters[*s1];
#			status = 1;
#			}
#		}
#	else
#		{
#			uint64_t m = (*hll_counters[*s2]).getM();
#			double error = 1.04/sqrt(m);
#			CardinalityCounter* newInst = new CardinalityCounter(error);
#			int i = 0;
#			while((*newInst).getM() != m)
#				{
#				i += 1;
#				newInst = new CardinalityCounter(error/i);
#				}
#			(*newInst).merge(hll_counters[*s2]);
#		if(hll_counters.count(*s1) < 1)
#			{
#			#hll_counters[*s1] = newInst;
#			}
#		else
#			{
#			delete hll_counters[*s1];
#			hll_counters[*s1] = newInst;
#			}
#		status = 1;
#		}
#	delete s1;
#	delete s2;
#	return new Val(status, TYPE_BOOL);
#	%}}

