# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function switch_one(v: any): string
	{
	switch (v) {
	case type string:
		return "String!";
	case type count:
		return "Count!";
	case type bool, type addr:
		return "Bool or address!";
	default:
		return "Something else!";
	}
	}

function switch_one_no_default(v: any): string
	{
	switch (v) {
	case type string:
		return "String!";
	case type count:
		return "Count!";
	case type bool, type addr:
		return "Bool or address!";
	}

	return "n/a";
	}

function test_set_vector_confusion(v: any)
	{
	# This used to treat "set[count]" as "vector of count" due to Zeek's
	# previous treatment of "is" to mean "converts to, in some cases".
	switch v {
	case type vector of count: print "vector-of-count"; break;
	case type set[count]: print "set[count]"; break;
	}
	}

event zeek_init()
	{
	print switch_one("string");
	print switch_one(42);
	print switch_one(T);
	print switch_one(1947/tcp);
	print "";
	print switch_one_no_default(1.2.3.4);
	print switch_one_no_default(1947/tcp);

	test_set_vector_confusion(vector(1, 3, 5));
	test_set_vector_confusion(set(2, 4, 6));
	}
