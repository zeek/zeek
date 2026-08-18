# For script optimization this test generates hard errors rather than warnings.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff-remove-abspath out
# @TEST-EXEC: btest-diff-remove-abspath err

event test()
	{
	local var_a: string = "foo";
	}

event test()
	{
	if ( F )
		{
		local var_b: string = "bar";
		}

	local var_a: string = "baz";

	print "var_a is", var_a;
	print "var_b is", var_b;
	}

event zeek_init()
	{
	event test();
	}
