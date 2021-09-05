# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff error

event zeek_init()
	{
	local a = vector(3.5, 1.2, -9.9, 12);
	local b = vector(2, 4, 6, 8);
	local c: vector of double;

	# The following requires correctly coercing 'b' to a vector-of-double
	# prior to doing the addition.
	c = a + b;

	print c;
	}

event zeek_init()
	{
	local v1 = vector(2,4);
	local v2 = vector(9,1);

	# Give both v1 and v2 a hole at index 2.
	v1[3] = 7;
	v2[3] = 100;

	# Give v1 a hole at 4 and v2 a hole at 5.
	v1[5] = 18;
	v1[6] = 999;

	v2[4] = 42;
	v2[6] = 47;

	print v1 + v2;

	# Make sure that holes get reflected in unary operations,
	# and also that vectors of count are properly coerced to
	# vectors of int.
	local v3: vector of int;
	v3 = -v1;
	print v3;
	}

event zeek_init()
	{
	local b = vector(2, -4, 6, 8);
	local c = vector(0xffffffffffffffff, 3, 5, 7);
	local d: vector of int;

	d = b + c;

	print d;
	}
