# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/supervisor.out
# @TEST-EXEC: btest-diff zeek/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff zeek/.stderr

# This test checks the default stdout/stderr redirection will get intercepted
# by the supervisor process and prefixed with the associated node name.

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global supervisor_output_file: file;
global topic = "test-topic";
global stderr = open("/dev/stderr");

event do_destroy()
	{
	print supervisor_output_file, "destroying node";
	Supervisor::destroy("grault");
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		Broker::subscribe(topic);
		Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
		supervisor_output_file = open("supervisor.out");
		print supervisor_output_file, "supervisor zeek_init()";
		local sn = Supervisor::NodeConfig($name="grault", $directory="qux");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print supervisor_output_file, res;
		}
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		print "(stdout) supervised node zeek_init()";
		print stderr, "(stderr) supervised node zeek_init()";
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Supervisor::is_supervised() )
		Broker::publish(topic, do_destroy);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	# Should only be run by supervisor
	terminate();
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		{
		print "(stdout) supervised node zeek_done()";
		print stderr, "(stderr) supervised node zeek_done()";
		}
	else
		print supervisor_output_file, "supervisor zeek_done()";
	}
