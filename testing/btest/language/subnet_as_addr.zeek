# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

function test_to_addr(sn: subnet, expect: addr)
	{
	local result = sn as addr;
	print fmt("%s as addr = %s (%s)", sn, result,
	          result == expect ? "SUCCESS" : "FAILURE");
	}

test_to_addr(0.0.0.0/32, 0.0.0.0);
test_to_addr(1.2.3.4/16, 1.2.0.0);
test_to_addr([2607:f8b0:4005:803::200e]/128, [2607:f8b0:4005:803::200e]);
