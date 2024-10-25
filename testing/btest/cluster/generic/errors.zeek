# @TEST-DOC: Test errors of cluster bifs
#
# @TEST-EXEC: zeek --parse-only -b %INPUT
# @TEST-EXEC: zeek -b %INPUT frameworks/cluster/backend/zeromq >zeromq.out 2>zeromq.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeromq.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeromq.out
# @TEST-EXEC: zeek -b %INPUT >broker.out 2>broker.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff broker.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff broker.out

event ping1(c: count, how: string) &is_used
	{
	}

hook hook1(c: count, how: string) &is_used
	{
	}

event zeek_init() &priority=-1
	{
	print "wrong number of args";

	Cluster::publish("topic");
	local r1 = Cluster::make_event();
	print "r1", r1;

	Cluster::publish("topic", ping1);
	local r2 = Cluster::make_event(ping1);
	print "r2", r2;

	Cluster::publish("topic", ping1, 1);
	local r3 = Cluster::make_event(ping1, 1);
	print "r3", r3;

	Cluster::publish("topic", ping1, 1, "args", 1.2.3.4);
	local r4 = Cluster::make_event(ping1, 1, "event", 1.2.3.4);
	print "r4", r4;
	}

event zeek_init() &priority=-2
	{
	print "wrong types";

	Cluster::publish("topic", ping1, 1, 2);
	local r1 = Cluster::make_event(ping1, 1, 2);
	print "r1", r1;

	Cluster::publish("topic", hook1, 1, "hook");
	local r2 = Cluster::make_event(hook1, 1, "hook");
	print "r2", r2;
	}
