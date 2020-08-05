
# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: LOGGER_PORT

# Test default log rotation/archival behavior (rotate into log-queue dir)
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: cp zeek/logger-1/log-queue/test*.log test.default.log
# @TEST-EXEC: btest-diff test.default.log
# @TEST-EXEC: rm -rf ./zeek

# Test rotation/archival behavior with in-flight compression
# @TEST-EXEC: btest-bg-run zeek zeek -j -b LogAscii::gzip_level=1 %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: gunzip -c zeek/logger-1/log-queue/test*.log.gz > test.zip-in-flight.log
# @TEST-EXEC: btest-diff test.zip-in-flight.log
# @TEST-EXEC: rm -rf ./zeek

# Test rotation/archival behavior with in-flight compression + custom file extension
# @TEST-EXEC: btest-bg-run zeek zeek -j -b LogAscii::gzip_level=1 LogAscii::gzip_file_extension="mygz" %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: cp zeek/logger-1/log-queue/test*.log.mygz test.log.gz
# @TEST-EXEC: gunzip -c test.log.gz > test.zip-in-flight-custom-ext.log
# @TEST-EXEC: btest-diff test.zip-in-flight-custom-ext.log
# @TEST-EXEC: rm -rf ./zeek

# Test rotation/archival behavior with a custom rotation dir
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT Log::default_rotation_dir=my-logs
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: cp zeek/logger-1/my-logs/test*.log test.custom-dir.log
# @TEST-EXEC: btest-diff test.custom-dir.log
# @TEST-EXEC: rm -rf ./zeek

@load base/frameworks/cluster

# JSON for log file brevity.
redef LogAscii::use_json=T;

global topic = "test-topic";

module Test;
export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}
module GLOBAL;

event pong()
	{
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
		Broker::peer("127.0.0.1", to_port(getenv("LOGGER_PORT")));

		local cluster: table[string] of Supervisor::ClusterEndpoint;
		cluster["logger-1"] = [$role=Supervisor::LOGGER, $host=127.0.0.1,
			$p=to_port(getenv("LOGGER_PORT"))];

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

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	}
