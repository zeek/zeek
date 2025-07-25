# @TEST-GROUP: broker
#
# @TEST-DOC: Limit the size of log lines that can be written.
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run logger "zeek -b ../logger.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "zeek -b ../worker-1.zeek"
# @TEST-EXEC: btest-bg-run worker-2 "zeek -b ../worker-2.zeek"
#
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff logger/weird.log
# @TEST-EXEC: btest-diff logger/test.log
# @TEST-EXEC: btest-diff worker-2/weird.log
# @TEST-EXEC: btest-diff worker-2/test.log

# @TEST-START-FILE common.zeek
@load base/frameworks/notice/weird

module Test;

# Disable the string and container length filtering.
redef Log::max_field_string_bytes = 0;
redef Log::max_total_string_bytes = 0;
redef Log::max_field_container_elements = 0;
redef Log::max_total_container_elements = 0;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		strings: vector of string &log;
	};
}

# Limit log lines to 1MB.
redef Log::max_log_record_size = 1024 * 1024;

redef Broker::disable_ssl = T;

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}
# @TEST-END-FILE

# @TEST-START-FILE logger.zeek
@load ./common.zeek

redef Log::enable_remote_logging = F;
redef Log::enable_local_logging = T;

event zeek_init()
	{
	Broker::subscribe("zeek/logs");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

global peers_lost = 0;

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	++peers_lost;
	if ( peers_lost == 2 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event do_write()
	{
	local s = "AAAAAAAAAAAAAAAAAAAA"; # 20 bytes
	local s100 = s + s + s + s + s;
	local s1000 = s100 + s100 + s100 + s100 + s100 + s100 + s100 + s100 + s100 + s100;

	local rec = Test::Info();
	local i = 0;
	while ( ++i <= ( 1000 * 1000 ) )
		{
		rec$strings += s1000;
		}

	Log::write(Test::LOG, rec);

	local rec2 = Test::Info();
	rec2$strings += "a";
	rec2$strings += "b";
	rec2$strings += "c";

	Log::write(Test::LOG, rec2);

	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "new_peer", msg;
	schedule 1sec { do_write() };
	}
# @TEST-END-FILE

# @TEST-START-FILE worker-1.zeek
@load ./worker.zeek
redef Log::enable_remote_logging = T;
redef Log::enable_local_logging = F;
# @TEST-END-FILE worker-1.zeek

# @TEST-START-FILE worker-2.zeek
@load ./worker.zeek
redef Log::enable_remote_logging = F;
redef Log::enable_local_logging = T;
# @TEST-END-FILE worker-2.zeek
