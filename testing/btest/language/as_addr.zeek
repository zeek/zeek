# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff error

function test_to_addr(ip: string, expect: addr)
	{
	if ( ip ?as addr )
		{
		local result = ip as addr;
		print fmt("%s as addr = %s (%s)", ip, result,
			  result == expect ? "SUCCESS" : "FAILURE");
		}
	else
		print fmt("%s as addr - conversion not allowed", ip);
	}

test_to_addr("0.0.0.0", 0.0.0.0);
test_to_addr("1.2.3.4", 1.2.3.4);
test_to_addr("01.02.03.04", 1.2.3.4);
test_to_addr("001.002.003.004", 1.2.3.4);
test_to_addr("10.20.30.40", 10.20.30.40);
test_to_addr("100.200.30.40", 100.200.30.40);
test_to_addr("10.0.0.0", 10.0.0.0);
test_to_addr("10.00.00.000", 10.0.0.0);
test_to_addr("not an IP", [::]);
