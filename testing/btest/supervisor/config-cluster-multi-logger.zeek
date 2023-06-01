
# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: LOGGER_PORT1
# @TEST-PORT: LOGGER_PORT2

# Run multiple loggers with the supervisor and verify the generated log files
# contain their node names as log_suffix metadata within the log-queue directory.
#
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: ls zeek/log-queue/test*logger-1__.log >> logs.out
# @TEST-EXEC: ls zeek/log-queue/test*logger-2__.log >> logs.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed "s/[0-9][0-9]/XX/g"' btest-diff logs.out

@load base/frameworks/cluster

# Make both loggers log into the same log-queue directory.
redef Log::default_rotation_dir = "../log-queue";

global topic = "test-topic";

module Test;
export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}
module GLOBAL;

global pong_count = 0;

event pong()
	{
	++pong_count;

	if ( pong_count == 2 )
		terminate();
	}

event ping()
	{
	Log::write(Test::LOG, [$s="test"]);
	Broker::publish(topic, pong);
	}

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Test::Log]);

	if ( Supervisor::is_supervisor() )
		{
		Broker::subscribe(topic);
		Broker::listen("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		Broker::peer("127.0.0.1", to_port(getenv("LOGGER_PORT1")));
		Broker::peer("127.0.0.1", to_port(getenv("LOGGER_PORT2")));

		local cluster: table[string] of Supervisor::ClusterEndpoint;
		cluster["logger-1"] = [
			$role=Supervisor::LOGGER,
			$host=127.0.0.1,
			$p=to_port(getenv("LOGGER_PORT1")),
		];

		cluster["logger-2"] = [
			$role=Supervisor::LOGGER,
			$host=127.0.0.1,
			$p=to_port(getenv("LOGGER_PORT2")),
		];

		for ( n, ep in cluster )
			{
			local sn = Supervisor::NodeConfig($name = n);
			sn$cluster = cluster;
			sn$directory = n;
			local res = Supervisor::create(sn);

			if ( res != "" )
				print fmt("failed to create node %s: %s", n, res);
			}
		}
	else
		{
		Broker::subscribe(topic);
		Broker::peer("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Supervisor::is_supervisor() )
		Broker::publish(topic, ping);
	}
