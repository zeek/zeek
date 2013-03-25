#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test -f testfile

event bro_init()
	{
	print capture_state_updates("testfile");
	}
