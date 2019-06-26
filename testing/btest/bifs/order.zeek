#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function myfunc1(a: addr, b: addr): int
	{
	local x = addr_to_counts(a);
	local y = addr_to_counts(b);
	if (x[0] < y[0])
		return -1;
	else
		return 1;
	}

function myfunc2(a: double, b: double): int
	{
	if (a < b)
		return -1;
	else
		return 1;
	}

event zeek_init()
	{

	# Tests without supplying a comparison function

	local a1 = vector( 5, 2, 8, 3 );
	local b1 = order(a1);
	print a1;
	print b1;

	local a2: vector of interval = vector( 5hr, 2days, 1sec, -7min );
	local b2 = order(a2);
	print a2;
	print b2;

	# Tests with a comparison function

	local c1: vector of addr = vector( 192.168.123.200, 10.0.0.157, 192.168.0.3 );
	local d1 = order(c1, myfunc1);
	print c1;
	print d1;

	local c2: vector of double = vector( 3.03, 3.01, 3.02, 3.015  );
	local d2 = order(c2, myfunc2);
	print c2;
	print d2;

	# Tests with large numbers

	local l1 = vector(2304, 1156, 13, 42, 4294967296);
	print l1;
	print order(l1);
	}
