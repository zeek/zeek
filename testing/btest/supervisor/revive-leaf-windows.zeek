# Windows variant of supervisor/revive-leaf.zeek.
#
# On Unix the supervised node kills itself via system("kill ...") to
# test that the supervisor framework revives it.  On Windows, MSYS
# bash's kill cannot target native Windows PIDs, so this variant
# uses terminate() for the self-kill which still triggers revival.

# @TEST-REQUIRES: is-windows
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
global peers_added = 0;

event kill_self()
	{
	terminate();
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
		Broker::subscribe(topic);
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		node_output_file = open("node.out");
		print node_output_file, "supervised node zeek_init()";
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers_added;

	if ( Supervisor::is_supervisor() )
		{
		print supervisor_output_file, "supervisor connected to peer";

		if ( peers_added == 3 )
			terminate();
		else
			Broker::publish(topic, kill_self);
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Supervisor::is_supervisor() )
		print supervisor_output_file, "supervisor lost peer";
	}

event zeek_done()
	{
	if ( Supervisor::is_supervisor() )
		print supervisor_output_file, "supervisor zeek_done()";
	else
		print node_output_file, "supervised node zeek_done()";
	}
