# @TEST-DOC: Test Cluster::raise_event behavior.
#
# @TEST-EXEC: zeek -b %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-remove-abspath .stderr

event test_event()
	{
	print "test_event";
	}

event test_event2(s: string, n: count)
	{
	print fmt("test_event2: %s, %s", s, n);
	}

event zeek_init() &priority=10
	{
	local e1 = Cluster::make_event(test_event);
	print Cluster::raise_event(e1);

	local e2 = Cluster::make_event(test_event2, "hello", 42);
	print Cluster::raise_event(e2);
	}
