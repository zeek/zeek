# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function switch_one(v: count): string
	{
	switch (v) {
	case 42:
		return "42!";
	case type count:
		return "Count!";
	}
	}

