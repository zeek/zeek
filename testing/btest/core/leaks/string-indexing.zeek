# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60


event new_connection(c: connection)
	{
	local s = "0123456789";
	print s[1];
	print s[1:2];
	print s[1:6];
	print s[0:20];
	print s[-2];
	print s[-3:1];
	print s[-1:10];
	print s[-1:0];
	print s[-1:5];
	print s[20:23];
	print s[-20:23];
	print s[0:5][2];
	print s[0:5][1:3][0];
	}
