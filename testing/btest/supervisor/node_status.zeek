# This test verifies that the Supervisor triggers Supervisor::node_status
# events when the stem (re)creates nodes.
#
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global status_count = 0;
global check_interval = 0.1sec;

event Supervisor::node_status(node: string, pid: count)
	{
	# We handle this once for the initial node creation, once for the
	# restart, then quit.
	if ( ++status_count == 2)
		terminate();

	print "got node_status event", node;

	# The status update has a PID for the new node, so checking node status
	# now should report a matching PID. This will output only in case the
	# PIDs do not match, failing the test.
	local s = Supervisor::status(node);
	local ns = s$nodes["grault"];

	if ( ! ns$pid )
		print "pid unavailable via Supervisor::status()", pid;
	else if ( ns$pid != pid )
		print "pid mismatch", ns$pid, pid;

	Supervisor::restart("grault");
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		local sn = Supervisor::NodeConfig($name="grault");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print "failed to create node", res;
		}
	}
