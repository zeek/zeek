# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global node_pid: int = 0;
global status_count = 0;
global check_interval = 0.1sec;

event check_status(name: string &default="")
	{
	local s = Supervisor::status(name);
	local ns = s$nodes["grault"];

	if ( ! ns?$pid )
		{
		schedule check_interval { check_status() };
		return;
		}

	if ( status_count > 0 && node_pid == ns$pid )
		{
		schedule check_interval { check_status() };
		return;
		}

	print "got supervised node status", ns$node$name;

	node_pid = ns$pid;
	++status_count;

	if ( status_count == 1 )
		{
		Supervisor::restart();
		schedule check_interval { check_status() };
		}
	else if ( status_count == 2 )
		{
		Supervisor::restart("grault");
		schedule check_interval { check_status("grault") };
		}
	else
		terminate();
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		local sn = Supervisor::NodeConfig($name="grault");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print "failed to create node", res;

		sn$name = "qux";
		res = Supervisor::create(sn);

		if ( res != "" )
			print "failed to create node", res;

		event check_status();
		}
	}
