# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"

# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv/test.log
# @TEST-EXEC: btest-diff send/send.out
# @TEST-EXEC: btest-diff send/test.log

@TEST-START-FILE common.zeek

redef exit_only_after_terminate = T;

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		msg: string &log;
		nolog: string &default="no";
		num: count &log;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(Test::LOG, [$columns=Test::Info]);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    terminate();
    }

event quit()
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek


@load ./common

event zeek_init()
	{
	Broker::subscribe("zeek/");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE send.zeek

@load ./common

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

global n = 0;
global done = F;

event die()
	{
	terminate();
	}

event do_write()
	{
	Log::write(Test::LOG, [$msg = "ping", $num = n]);
	++n;

	if ( n == 1 )
		schedule .1secs { do_write() };
	else
		done = T;
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "Broker::peer_added", endpoint$network$address;
    event do_write();
    }

module Broker;

event Broker::log_flush()
	{
	if ( done )
		Broker::publish("zeek/quit", quit);
	}

@TEST-END-FILE
