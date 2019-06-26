# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_noop()
	{
	while ( F )
		print "noooooooooo";
	}

function test_it()
	{
	local i = 0;

	while ( i < 10 )
		++i;

	print i;
	}

function test_break()
	{
	local s = "";

	while ( T )
		{
		s += "s";
		print s;

		if ( s == "sss" )
			break;
		}
	}

function test_next()
	{
	local s: set[count];
	local i = 0;

	while ( 9 !in s )
		{
		++i;

		if ( i % 2 == 0 )
			next;

		add s[i];
		}

	print s;
	}

function test_return(): vector of string
	{
	local i = 0;
	local rval: vector of string;

	while ( T )
		{
		rval[i] = fmt("number %d", i);
		++i;

		if ( i == 13 )
			return rval;
		}

	rval[0] = "noooo";
	return rval;
	}

event zeek_init()
	{
	test_noop();
	test_it();
	test_break();
	test_next();
	print test_return();
	}
