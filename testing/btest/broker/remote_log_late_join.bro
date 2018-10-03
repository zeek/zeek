# @TEST-SERIALIZE: comm

# @TEST-EXEC: btest-bg-run recv "bro -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -b ../send.bro >send.out"

# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv/test.log
# @TEST-EXEC: btest-diff send/send.out
# @TEST-EXEC: btest-diff send/test.log

@TEST-START-FILE common.bro

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

event bro_init() &priority=5
	{
	Log::create_stream(Test::LOG, [$columns=Test::Info]);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    terminate();
    }

@TEST-END-FILE

@TEST-START-FILE recv.bro


@load ./common.bro

event bro_init()
	{
	Broker::subscribe("bro/");
	Broker::listen("127.0.0.1");
	}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@TEST-END-FILE

@TEST-START-FILE send.bro



@load ./common.bro

event doconnect()
	{
	Broker::peer("127.0.0.1");
	}

global n = 0;

event bro_init()
	{
	schedule 2secs { doconnect() };
	Log::write(Test::LOG, [$msg = "ping", $num = n]);
	++n;
	}

event die()
	{
	terminate();
	}

event do_write()
	{
	if ( n == 6 )
		{
		Broker::flush_logs();
		schedule 1sec { die() };
		}
	else
		{
		Log::write(Test::LOG, [$msg = "ping", $num = n]);
		++n;
		schedule 0.1secs { do_write() };
		}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "Broker::peer_added", endpoint$network$address;
    event do_write();
    }


@TEST-END-FILE
