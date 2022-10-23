# This test verifies the functionality of the bare_mode flag in NodeConfig.
# We launch two nodes, one regular, one in bare mode. Each outputs a different
# string depending on mode, and exits. We verify the resulting outputs.

# @TEST-PORT: BROKER_PORT
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/inherit/node.out
# @TEST-EXEC: btest-diff zeek/bare/node.out
# @TEST-EXEC: btest-diff zeek/default/node.out


# So the supervised node doesn't terminate right away.
redef exit_only_after_terminate=T;

global node_output_file: file;
global topic = "test-topic";

event do_destroy(name: string)
	{
	Supervisor::destroy(name);

	# When no nodes are left, exit.
	local status = Supervisor::status();
	if ( |status$nodes| == 0)
		terminate();
	}

event zeek_init()
	{
	if ( Supervisor::is_supervisor() )
		{
		Broker::subscribe(topic);
		Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));

		# Create a node that inherits base mode from us.
		local sn = Supervisor::NodeConfig($name="inherit", $directory="inherit");
		Supervisor::create(sn);

		# Create a node that specifies bare mode.
		sn = Supervisor::NodeConfig($name="bare", $directory="bare", $bare_mode=T);
		Supervisor::create(sn);

		# Create a node that specifies default mode.
		sn = Supervisor::NodeConfig($name="default", $directory="default", $bare_mode=F);
		Supervisor::create(sn);

		}
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		node_output_file = open("node.out");
		print node_output_file, "supervised node zeek_init()";

# This is only defined when we're loading init-default.zeek:
@ifdef ( Conn::LOG )
		print node_output_file, "default mode";
@else
		print node_output_file, "bare mode";
@endif
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Supervisor::is_supervised() )
		Broker::publish(topic, do_destroy, Supervisor::node()$name);
	}

event zeek_done()
	{
	if ( Supervisor::is_supervised() )
		print node_output_file, "supervised node zeek_done()";
	}
