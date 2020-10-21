# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests whether script optimizer generates correct code for loops that
# can be re-entered due to recursion.  For each form of vector/string/table,
# we test both a directly-recursive function and an indirectly-recursive
# variant.

global indirect_rec_vector_helper: function(a: vector of count, n: count);

function direct_recursive_vector(a: vector of count, n: count)
	{
	for ( i in a )
		{
		print i, a[i], n;
		if ( i > 0 )
			direct_recursive_vector(a[i:|a|], n + 1);
		}
	}

function indirect_recursive_vector(a: vector of count, n: count)
	{
	for ( i in a )
		{
		print i, a[i], n;
		if ( i > 0 )
			indirect_rec_vector_helper(a[i:|a|], n + 1);
		}
	}

function indirect_rec_vector_helper(a: vector of count, n: count)
	{
	indirect_recursive_vector(a, n);
	}


global indirect_rec_string_helper: function(a: string, n: count);

function direct_recursive_string(a: string, n: count)
	{
	print a, n;

	if ( |a| > 1 )
		for ( i in a )
			direct_recursive_string(i, n + 1);
	}

function indirect_recursive_string(a: string, n: count)
	{
	print a, n;

	if ( |a| > 1 )
		for ( i in a )
			indirect_rec_string_helper(i, n + 1);
	}

function indirect_rec_string_helper(a: string, n: count)
	{
	indirect_recursive_string(a, n);
	}


global indirect_rec_table_helper: function(a: table[count] of count, n: count): count;

function direct_recursive_table(a: table[count] of count, n: count): count
	{
	if ( n == 0 )
		return 0;

	local sum = 0;
	for ( i in a )
		{
		sum += a[i];
		sum += direct_recursive_table(a, n - 1);
		}

	return sum;
	}

function indirect_recursive_table(a: table[count] of count, n: count): count
	{
	if ( n == 0 )
		return 0;

	local sum = 0;
	for ( i in a )
		{
		sum += a[i];
		sum += indirect_rec_table_helper(a, n - 1);
		}

	return sum;
	}

function indirect_rec_table_helper(a: table[count] of count, n: count): count
	{
	return indirect_recursive_table(a, n);
	}


event zeek_init()
	{
	local x = vector(5, 4, 3, 2, 1);
	direct_recursive_vector(x, 0);
	indirect_recursive_vector(x, 0);

	local y = "foobar";
	direct_recursive_string(y, 0);
	indirect_recursive_string(y, 0);

	local z: table[count] of count;
	z[42] = 24;
	z[24] = 43;
	z[0] = 88;

	print direct_recursive_table(z, 3);
	print indirect_recursive_table(z, 3);
	}
