# @TEST-EXEC: zeek -b %INPUT >output 2>error
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff error

function test_to_addr(sn: subnet, expect: addr)
	{
	local result = subnet_to_addr(sn);
	print fmt("subnet_to_addr(%s) = %s (%s)", sn, result,
	          result == expect ? "SUCCESS" : "FAILURE");
	}

test_to_addr(0.0.0.0/32, 0.0.0.0);
test_to_addr(1.2.3.4/16, 1.2.0.0);
test_to_addr([2607:f8b0:4005:803::200e]/128, [2607:f8b0:4005:803::200e]);
