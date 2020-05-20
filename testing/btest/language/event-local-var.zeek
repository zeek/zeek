# @TEST-EXEC-FAIL: zeek -b %INPUT 2> out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out


event e1(num: count)
	{
	print fmt("event 1: %s", num);
	}

event zeek_init()
{
	# Test assigning a local event variable to an event
	local v: event(num: count);
	v = e1;
	schedule 1sec { v(6) };  # This should fail
}
