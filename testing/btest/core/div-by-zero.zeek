# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global v1 = vector(10, 20, 30);
global v2 = vector(5, 2, 0);

event div_int(a: int, b: int)
	{
	print a / b;
	}

event div_count(a: count, b: count)
	{
	print a / b;
	}

event div_double(a: double, b: double)
	{
	print a / b;
	}

event div_vec()
	{
	print v1 / v2;
	}

event mod_int(a: int, b: int)
	{
	print a % b;
	}

event mod_count(a: count, b: count)
	{
	print a % b;
	}

event mod_vec()
	{
	print v1 % v2;
	}

event zeek_init()
	{
	event div_int(10, 0);
	event div_count(10, 0);
	event div_double(10.0, 0.0);
	event mod_int(10, 0);
	event mod_count(10, 0);
	event div_vec();
	event mod_vec();
	}
