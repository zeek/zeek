# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -b -m %INPUT
# @TEST-EXEC: btest-bg-wait 60

event x()
	{
	print("X");
	}

event bro_init()
	{
	schedule 1sec { x() };
	print async __test_trigger("test", 2.25secs, 5.0secs); # No timeout
	print async __test_trigger("test", 5.0secs, 2.25secs); # Timeout
	terminate();
	}
