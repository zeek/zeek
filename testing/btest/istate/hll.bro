# @TEST-EXEC: bro -b %INPUT runnumber=1 >out
# @TEST-EXEC: bro -b %INPUT runnumber=2 >>out
# @TEST-EXEC: bro -b %INPUT runnumber=3 >>out
# @TEST-EXEC: btest-diff out

global runnumber: count &redef; # differentiate first and second run

global card: opaque of cardinality &persistent;

event bro_init()
	{
	print runnumber;

	if ( runnumber == 1 )
		{
		card = hll_cardinality_init(0.01, 0.95);

		hll_cardinality_add(card, "a");
		hll_cardinality_add(card, "b");
		hll_cardinality_add(card, "c");
		hll_cardinality_add(card, "d");
		hll_cardinality_add(card, "e");
		hll_cardinality_add(card, "f");
		hll_cardinality_add(card, "g");
		hll_cardinality_add(card, "h");
		hll_cardinality_add(card, "i");
		hll_cardinality_add(card, "j");
		}

	print hll_cardinality_estimate(card);

		if ( runnumber == 2 )
		{
		hll_cardinality_add(card, "a");
		hll_cardinality_add(card, "b");
		hll_cardinality_add(card, "c");
		hll_cardinality_add(card, "aa");
		}
	}

