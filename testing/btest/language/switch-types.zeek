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


event zeek_init()
	{
	print switch_one("string");
	print switch_one(42);
	print switch_one(T);
	print switch_one(1947/tcp);
	print "";
	print switch_one_no_default(1.2.3.4);
	print switch_one_no_default(1947/tcp);
	
	}
