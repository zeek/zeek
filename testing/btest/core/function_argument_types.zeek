# @TEST-EXEC: zeek -b %INPUT 1> my_output 2> my_error
# @TEST-EXEC: btest-diff my_output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff my_error

global s: set[string, string];

function sort_set(s: set[string]): vector of string
	{
	local v: vector of string = vector();

	for ( e in s )
		v += e;

	sort(v, strcmp);
	return v;
	}

event zeek_init()
	{
	add s["hi", "there"];
	sort_set(s);
	}