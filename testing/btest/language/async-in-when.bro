# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event done()
	{
	terminate();
	}

function test(label: string, delay: interval, trigger_timeout: interval)
	{
	when ( local r = __test_trigger("result", delay, trigger_timeout) ) 
		{
		print fmt("%s: got '%s'", label, r);
		}
	timeout 4secs
		{
		print fmt("%s: WHEN-TIMEOUT", label);
		}
	}

event bro_init()
	{
	schedule 5sec { done() };

	test("no timeout", 1.0secs, 10secs);
	test("trigger timeout", 10sec, 1.0secs);
	test("when timeout", 10sec, 10.0secs);
	}
