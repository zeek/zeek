# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


event e1()
	{
	print "event statement";
	return;
	print "Error: this should not happen";
	}

event e2(s: string)
	{
	print fmt("schedule statement %s", s);
	}

event e3(test: string)
	{
	print "event part1";
	}

event e4(num: count)
	{
	print fmt("assign event variable (%s)", num);
	}

# Note: the name of this event is intentionally the same as one above
event e3(test: string)
	{
	print "event part2";
	}

global e5: event(num: count);

event zeek_init()
{
	# Test calling an event with "event" statement
	event e1();

	# Test calling an event with "schedule" statement
	schedule 1 sec { e2("in zeek_init") };
	schedule 3 sec { e2("another in zeek_init") };

	# Test calling an event that has two separate definitions
	event e3("foo");

	# Test assigning an event variable to an event
	e5 = e4;
	event e5(6);
}

# scheduling in outside of an event handler shouldn't crash.
schedule 2sec { e2("in global") };
