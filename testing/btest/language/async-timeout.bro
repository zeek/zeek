# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

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
