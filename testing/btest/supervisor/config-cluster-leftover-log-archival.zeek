# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: LOGGER_PORT

# Test default leftover log rotation/archival behavior
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: cp zeek/logger-1/test*.log test.default.log
# @TEST-EXEC: btest-diff test.default.log
# @TEST-EXEC: rm -rf ./zeek

# Test leftover log rotation/archival behavior with custom postprocessor func
# @TEST-EXEC: btest-bg-run zeek zeek -j -b %INPUT use_custom_postproc=T
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: cp zeek/logger-1/test*.log test.postproc.log
# @TEST-EXEC: btest-diff test.postproc.log
# @TEST-EXEC: btest-diff zeek/logger-1/postproc.out
# @TEST-EXEC: rm -rf ./zeek

@load base/frameworks/cluster

option use_custom_postproc = F;

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

module LogAscii;
export {
function my_rotation_postprocessor(info: Log::RotationInfo) : bool
	{
	local f = open("postproc.out");
	print f, "running my rotation postprocessor";
	close(f);
	return LogAscii::default_rotation_postprocessor_func(info);
	}
}
module GLOBAL;

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Test::Log]);

	if ( use_custom_postproc )
		{
		local df = Log::get_filter(Test::LOG, "default");
		df$postprocessor = LogAscii::my_rotation_postprocessor;
		Log::add_filter(Test::LOG, df);
		}

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

			# Hard to test the full process of a kill/crash leaving these
			# leftover files, so just fake them.
			mkdir(sn$directory);
			local f = open(fmt("%s/test.log", sn$directory));
			print f, "{\"s\":\"leftover test\"}";
			close(f);
			local sf = open(fmt("%s/.shadow.test.log", sn$directory));
			print sf, ".log";

			if ( use_custom_postproc )
				print sf, "LogAscii::my_rotation_postprocessor";
			else
				print sf, "";

			close(sf);

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
		terminate();
	}
