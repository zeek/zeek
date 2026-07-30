# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

function switch_one(v: any): string
	{
	switch (v) {
	case type string:
		return "String!";
	case type count:
		return "Count!";
	case type bool, type count:
		return "Bool or address!";
	default:
		return "Something else!";
	}

	}

