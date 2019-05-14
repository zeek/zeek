#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test -f testfile

event zeek_init()
	{
	print capture_state_updates("testfile");
	}
