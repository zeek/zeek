# @TEST-EXEC: zeek -b %INPUT 2>&1 | grep -o "argument type mismatch in function call" > out
# @TEST-EXEC: btest-diff out

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