# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff error

function test_to_addr(ip: string, expect: addr)
	{
	local result = to_addr(ip);
	print fmt("to_addr(%s) = %s (%s)", ip, result,
	          result == expect ? "SUCCESS" : "FAILURE");
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
