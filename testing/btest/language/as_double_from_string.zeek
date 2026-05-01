# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

function test_to_double(d: string, expect: double)
	{
	if ( d ?as double )
		{
		local result = d as double;
		print fmt("%s as double = %s (%s)", d, result,
			  result == expect ? "SUCCESS" : "FAILURE");
		}
	else
		print fmt("%s as double - conversion not allowed", d);
	}

test_to_double("3.14", 3.14);
test_to_double("-3.14", -3.14);
test_to_double("0", 0);
test_to_double("NotADouble", 0);
test_to_double("", 0);
