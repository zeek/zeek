# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# @TEST-DOC: Test for type-checking of function call arguments.

global s: set[string, string];

function sort_set(s: set[string]): vector of string
	{
	local v: vector of string = vector();

	for ( e in s )
		v += e;

	sort(v, strcmp);
	return v;
	}

add s["hi", "there"];
# This sort_set call should warn about mismatched table/set types.
sort_set(s);

