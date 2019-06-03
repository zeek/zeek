# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


event zeek_init()
	{
	# Test single keys

	local t: table[count] of string = table();
	t[1] = "hello";
	t[55] = "goodbye";
	for (key, value in t)
		print key, value;

	# Test multiple keys

	local tkk: table[string, string] of count = table();
	tkk["hello", "world"] = 1;
	tkk["goodbye", "world"] = 55;
	for ([k1, k2], val in tkk)
		print k1, k2, val;
	}
