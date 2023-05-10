# @TEST-DOC: Disable network_time forward on a worker and let a manager completely drive its network_time.
# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run manager "zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker "zeek -b ../worker.zeek"
# @TEST-EXEC: btest-bg-wait 5

# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff worker/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff manager/.stdout

@TEST-START-FILE worker.zeek

redef allow_network_time_forward = F;

global timer_tock: event();

event zeek_init()
	{
	print network_time(), "zeek_init: broker peering";
        Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	Broker::subscribe("zeek/event/my_topic");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print network_time(), "Broker::peer_added";
        }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
        print network_time(), "[FAIL] Broker::peer_lost";
	exit(1);
	}

event timer(s: string)
	{
	print fmt("%.3f", network_time()), "timer", s;
	}

# The manager sends timer_tick() with the network time to the worker which
# replies back with a timer_tock().
global received_ticks = 0;
event timer_tick(ts: time) &is_used
	{
	++received_ticks;
	print fmt("%.3f", network_time()), "timer_tick", received_ticks, ts;
	set_network_time(ts);

	# On the first tick, schedule a few timer for the future so
	# that we can observe them expire.
	if ( received_ticks == 1 )
		{
		schedule 0.5sec { timer("first timer (1 sec)") };
		schedule 3sec { timer("second timer (3 sec)") };
		schedule 3.25sec { timer("third timer (3.25 sec)") };
		schedule 5sec { timer("fourth timer (10 sec)") };
		}

	Broker::publish("zeek/event/my_topic", timer_tock);

	if ( received_ticks == 30 )
		terminate();
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
@TEST-END-FILE


@TEST-START-FILE manager.zeek
# The manager waits for a peer to appear, then starts sending timer
# ticks until the peer is gone again.
global timer_tick: event(ts: time);

global fake_network_time = double_to_time(42.0);

event zeek_init()
	{
	print "manager: listening";
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	Broker::subscribe("zeek/event/my_topic");
	}

# Received from the worker once it has processed the tick.
event timer_tock() &is_used
	{
	fake_network_time = fake_network_time + double_to_interval(0.25);
	Broker::publish("zeek/event/my_topic", timer_tick, fake_network_time);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "manager: peer added, publishing timer_tick() events";
	Broker::publish("zeek/event/my_topic", timer_tick, fake_network_time);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "manager: peer lost, terminating";
	terminate();
	}
@TEST-END-FILE
