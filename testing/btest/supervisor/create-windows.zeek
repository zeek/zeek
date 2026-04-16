# Windows variant of supervisor/create.zeek.
#
# On Unix the supervised node terminates the supervisor via
# system("kill ...") which delivers SIGTERM for a graceful shutdown.
# Windows has no equivalent external graceful-termination signal, so
# this variant uses Broker to let the supervised node tell the
# supervisor that creation succeeded, then shuts down the tree via
# Supervisor::destroy() + terminate().

# @TEST-REQUIRES: is-windows
# @TEST-REQUIRES: ! is-windows-ci
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

event node_created()
	{
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
		local sn = Supervisor::NodeConfig($name="grault");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print supervisor_output_file, res;
		}
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		node_output_file = open("node.out");
		print node_output_file, "supervised node zeek_init()";
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Supervisor::is_supervised() )
		Broker::publish(topic, node_created);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		print node_output_file, "supervised node zeek_done()";
	else
		print supervisor_output_file, "supervisor zeek_done()";
	}
