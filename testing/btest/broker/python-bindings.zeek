# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-DOC: biswa on community.zeek.org has been doing cool stuff with zeek -r, Python broker bindings and suspend_processing(). He ran into a number of issues around suspend_processing(), time management, etc, try to cover some here.
#
# @TEST-REQUIRES: python3 -V
# @TEST-REQUIRES: TOPIC=/btest/connections python3 recv.py check
#
# @TEST-EXEC: TOPIC=/btest/connections btest-bg-run recv "python3 -u ../recv.py"
# @TEST-EXEC: TOPIC=/btest/connections btest-bg-run send "zeek -f 'port 80' -b ../send.zeek -r $TRACES/wikipedia.trace"
#
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff recv/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff send/.stdout

@TEST-START-FILE send.zeek

global new_conn_added: event(c: connection) &is_used;
global conn_removed: event(c: connection) &is_used;

global my_topic = getenv("TOPIC");

global conn_events = 0;

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	Broker::subscribe(my_topic);
	suspend_processing();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print network_time(), "peer lost";
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print network_time(), "peer added";
	continue_processing();
	}

event new_connection(c: connection)
	{
	++conn_events;
	print network_time(), "new_connection", conn_events, c$uid;
	Broker::publish(my_topic, new_conn_added, c);
	}

event connection_state_remove(c: connection)
	{
	++conn_events;
	print network_time(), "connection_state_remove", conn_events, c$uid;
	Broker::publish(my_topic, conn_removed, c);
	}

event send_pcap_file_done(path: string)
	{
	print network_time(), "send_pcap_file_done";
	Broker::publish(my_topic, Pcap::file_done, path);
	}

event Pcap::file_done(path: string)
	{
	# Done reading pcap, forward network_time() by
	# 24 hours to expire timers. Send Pcap::file_done
	# to Python in a schedule timer to initiate
	# termination.
	print network_time(), "Pcap::file_done";

	schedule double_to_interval(24 * 3600 - 1) { send_pcap_file_done(path) };

	set_network_time(network_time() + double_to_interval(24 * 3600));
	}

global events_from_python = 0;
event echo_from_python(what: string, c: connection) &is_used
	{
	++events_from_python;
	print network_time(), "from_python", events_from_python, what, c$uid, c$id;
	}
@TEST-END-FILE


@TEST-START-FILE recv.py
"""
Python script subscribing to TOPIC
"""
import os
import sys

# Prep the PYTHONPATH for the build directory.
broker_path = os.path.join(os.environ["BUILD"], "auxil", "broker", "python")
sys.path.insert(0, broker_path)

import broker

# 1024/tcp
broker_port = int(os.environ["BROKER_PORT"].split("/")[0])
broker_topic = os.environ["TOPIC"]

# We were able to import broker and parse the broker_port, should be good.
if len(sys.argv) > 1 and sys.argv[1] == "check":
    sys.exit(0)

# Setup endpoint and connect to Zeek.
with ( broker.Endpoint() as ep,
     ep.make_subscriber(broker_topic) as sub,
     ep.make_status_subscriber(True) as ss):

    ep.listen("127.0.0.1", broker_port)

    while True:
        statuses = ss.poll()
        for s in statuses:
            if s.code() in (broker.SC.PeerLost, broker.SC.EndpointUnreachable):
                print("peer lost, done")
                exit(0)

        # Busy poll for a message or later status
        msg = sub.get(0.5)
        if msg is None:
            continue
        (t, d) = msg
        my_event = broker.zeek.Event(d)
        conn = my_event.args()[0]
        print("Received", t, my_event.name(), my_event.args()[0][0])

        if my_event.name() == "Pcap::file_done":
            print("Received Pcap::file_done")
            break

        other_event = broker.zeek.Event("echo_from_python", my_event.name(), conn)
        ep.publish(broker_topic, other_event)
@TEST-END-FILE
