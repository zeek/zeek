# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function switch_one(v: string): string
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

