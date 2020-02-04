# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

event check_status()
	{
	local s = Supervisor::status();
	local ns = s$nodes["grault"];

	if ( ! ns?$pid )
		schedule 0.25sec { check_status() };
	else
		{
		print "got supervised node status", ns$node$name;
		terminate();
		}
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		local sn = Supervisor::NodeConfig($name="grault");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print "failed to create node", res;

		event check_status();
		}
	}
