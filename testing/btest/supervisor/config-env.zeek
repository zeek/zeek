# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/supervisor.out
# @TEST-EXEC: btest-diff zeek/node.out

# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global supervisor_output_file: file;
global node_output_file: file;
global topic = "test-topic";

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
		local sn = Supervisor::NodeConfig($name="grault", $env=table(
			["foo"] = "bar"
		));
		local res = Supervisor::create(sn);

		if ( res != "" )
			print supervisor_output_file, res;
		}
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		node_output_file = open("node.out");
		print node_output_file, fmt("supervised node zeek_init() with env foo=%s", getenv("foo"));
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
		print node_output_file, "supervised node zeek_done()";
	else
		print supervisor_output_file, "supervisor zeek_done()";
	}
