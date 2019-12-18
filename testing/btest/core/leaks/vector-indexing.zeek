# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 90

global did_it = F;

event new_connection(c: connection)
	{
	if ( did_it )
		return;

	did_it = T;

	# Slicing tests.
	local v17 = vector( 1, 2, 3, 4, 5 );
	print v17[0:2];
	print v17[-3:-1];
	print v17[:2];
	print v17[2:];
	print v17[:];
	v17[0:1] = vector(6);
	v17[2:4] = vector(7, 8);
	v17[2:4] = vector(9, 10, 11);
	v17[2:5] = vector(9);
	}
