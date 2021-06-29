# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/supervisor.out
# @TEST-EXEC: btest-diff zeek/node.out

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global supervisor_output_file: file;
global node_output_file: file;

event zeek_init()
	{
	local pid_file = "supervisor.pid";

	if ( Supervisor::is_supervisor() )
		{
		supervisor_output_file = open("supervisor.out");
		print supervisor_output_file, "supervisor zeek_init()";
		local f = open(pid_file);
		print f, getpid();

		# The following is needed for ZAM code, which will otherwise
		# keep the file open until the corresponding frame slot
		# is reused or (finally) goes out of scope.
		close(f);

		local sn = Supervisor::NodeConfig($name="grault");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print supervisor_output_file, res;
		}
	else
		{
		node_output_file = open("node.out");
		print node_output_file, "supervised node zeek_init()";
		system(fmt("kill `cat %s`", pid_file));
		}
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		print node_output_file, "supervised node zeek_done()";
	else
		print supervisor_output_file, "supervisor zeek_done()";
	}
