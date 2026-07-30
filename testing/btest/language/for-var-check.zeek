# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out

global x: count = 0;

event zeek_init()
	{
	const y: count = 0;

	for ( x in set(1, 2, 3) ) {}
	for ( y in set(1, 2, 3) ) {}
	}

