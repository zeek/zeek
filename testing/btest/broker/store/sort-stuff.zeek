# @TEST-IGNORE

function sort_set(s: set[string]): vector of string
	{
	local v: vector of string = vector();

	for ( e in s )
		v += e;

	sort(v, strcmp);
	return v;
	}

type TableEntry: record {
	key: string;
	val: any;
};

function sort_table(t: table[string] of any): vector of TableEntry
	{
	local vs: vector of string = vector();
	local rval: vector of TableEntry = vector();

	for ( k, v in t )
		vs += k;

	sort(vs, strcmp);

	for ( i in vs )
		rval += TableEntry($key=vs[i], $val=t[vs[i]]);

	return rval;
	}
