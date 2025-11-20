# Run a cluster with 64 Zeek processes and an insanely large cluster
# layout (which is sent over the supervisor <-> stem pipe for every
# Supervisor::create() call. This previously triggered an instant-abort()
# due to write() returning with EAGAIN when the pipe was filled.

# @TEST-PORT: BROKER_PORT
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: btest-diff zeek/bare-1/node.out
# @TEST-EXEC: btest-diff zeek/bare-32/node.out

@load base/frameworks/cluster
@load frameworks/cluster/backend/broker

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

		local i = 0;
		local name: string;
		local cluster: table[string] of Supervisor::ClusterEndpoint;
		while ( ++i <= 1024 )
			{
			name = fmt("bare-%d", i);
			cluster[name] = [$host=127.0.0.1, $p=0/tcp, $role=Supervisor::WORKER];
			}

		i = 0;
		while ( ++i <= 32 )
			{
			name = fmt("bare-%d", i);
			local sn = Supervisor::NodeConfig($name=name, $directory=name, $bare_mode=T, $cluster=cluster);
			Supervisor::create(sn);
			}
		}
	else
		{
		Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
		node_output_file = open("node.out");
		print node_output_file, "supervised node zeek_init()";
		print node_output_file, |Cluster::nodes|, "cluster_nodes!";
		print node_output_file, Cluster::nodes[Cluster::node];
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
