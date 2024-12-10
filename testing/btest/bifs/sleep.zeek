# Verifies sleep()'s reported latencies.
#
# @TEST-EXEC: zeek -b %INPUT 2>out
# @TEST-EXEC: btest-diff out

function test_sleep(i: interval)
	{
	local start = current_time();
	local sleep_delay = sleep(i);
	local script_delay = current_time() - start;

	assert script_delay >= i, fmt("sleep() took %s, less than %s", script_delay, i);
	assert sleep_delay >= i, fmt("slept for %s, less than %s", script_delay, i);
	assert sleep_delay <= script_delay, fmt("sleep() claims %s, longer than %s", sleep_delay, script_delay);
	}

event zeek_init()
	{
	test_sleep(100msec);
	test_sleep(1sec);
	}
