# @TEST-EXEC: bro -b %INPUT >output
# @TEST-EXEC: btest-diff output

# The various container constructor expressions should work in table
# initialization lists.

type set_yield: set[string, count];
type vector_yield: vector of count;
type table_yield: table[string, count] of count;

global lone_set_ctor: set_yield = set(["foo", 1], ["bar", 2]);
global lone_vector_ctor: vector_yield = vector(1, 2);
global lone_table_ctor: table_yield = table(["foo", 1] = 1, ["bar", 2] = 2);

global table_of_set: table[count] of set_yield = {
	[13] = lone_set_ctor,
	 [5] = set(["bah", 3], ["baz", 4]),
};

global table_of_vector: table[count] of vector_yield = {
	[13] = lone_vector_ctor,
	 [5] = vector(3, 4),
};

global table_of_table: table[count] of table_yield = {
	[13] = lone_table_ctor,
	 [5] = table(["bah", 3] = 3, ["baz", 4] = 4),
};

# Just copying the inline ctors used in the table initializer lists here
# for later comparisons.
global inline_set_ctor: set_yield = set(["bah", 3], ["baz", 4]);
global inline_vector_ctor: vector_yield = vector(3, 4);
global inline_table_ctor: table_yield = table(["bah", 3] = 3, ["baz", 4] = 4);

function compare_set_yield(a: set_yield, b: set_yield)
	{
	local s: string;
	local c: count;
	for ( [s, c] in a )
		print [s, c] in b;
	}

function compare_vector_yield(a: vector_yield, b: vector_yield)
	{
	local c: count;
	for ( c in a )
		print a[c] == b[c];
	}

function compare_table_yield(a: table_yield, b: table_yield)
	{
	local s: string;
	local c: count;
	for ( [s, c] in a )
		print [s, c] in b && a[s, c] == b[s, c];
	}

print "table of set";
print table_of_set;
print "";
print "table of vector";
print table_of_vector;
print "";
print "table of table";
print table_of_table;
print "";

compare_set_yield(table_of_set[13], lone_set_ctor);
compare_set_yield(table_of_set[5], inline_set_ctor);
compare_vector_yield(table_of_vector[13], lone_vector_ctor);
compare_vector_yield(table_of_vector[5], inline_vector_ctor);
compare_table_yield(table_of_table[13], lone_table_ctor);
compare_table_yield(table_of_table[5], inline_table_ctor);
