# @TEST-GROUP: leaks
# @TEST-REQUIRES: zeek --help 2>&1 | grep -q mem-leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

event new_connection(c: connection)
	{
	local t: table[count] of string = table();
	t[1] = "hello";
	t[55] = "goodbye";

	for (key, value in t)
		print key, value;

	local tkk: table[string, string] of count = table();
	tkk["hello", "world"] = 1;
	tkk["goodbye", "world"] = 55;

	for ([k1, k2], val in tkk)
		print k1, k2, val;
	}
