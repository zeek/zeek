# @TEST-DOC: Test compatibility with peers sending events without timestamps.
#
# @TEST-GROUP: broker
# @TEST-PORT: BROKER_PORT
#
# @TEST-REQUIRES: python3 -V
# @TEST-REQUIRES: TOPIC=/zeek/my_topic python3 client.py check
#
# @TEST-EXEC: TOPIC=/zeek/my_topic btest-bg-run server "zeek %INPUT >output"
# @TEST-EXEC: TOPIC=/zeek/my_topic btest-bg-run client "python3 ../client.py >output"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff server/output
# @TEST-EXEC: btest-diff client/output

redef exit_only_after_terminate = T;
redef allow_network_time_forward = F;

event zeek_init()
	{
	Broker::subscribe(getenv("TOPIC"));
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	set_network_time(double_to_time(42.0));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	terminate();
	}

event my_event(msg: string) &is_used
	{
	print fmt("got my_event(%s) stamped to %s at network time %s",
		msg, current_event_time(), network_time());
	}


@TEST-START-FILE client.py
"""
Python script sending timestamped and non-timestamped event to TOPIC
"""
import datetime
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
with broker.Endpoint() as ep, \
	 ep.make_status_subscriber(True) as ss:

	ep.peer("127.0.0.1", broker_port)
	st = ss.get(2)
	if not (st[0].code() == broker.SC.EndpointDiscovered and
		    st[1].code() == broker.SC.PeerAdded):
		print("could not connect")
		exit(0)

	# Send events and close connection
	print("send event without timestamp")
	my_event = broker.zeek.Event("my_event", "without ts")
	ep.publish(broker_topic, my_event)

	print("send event with timestamp")
	ts = datetime.datetime.fromtimestamp(23.0, broker.utc)
	metadata = {
		broker.zeek.MetadataType.NetworkTimestamp: ts,
	}
	my_event = broker.zeek.Event("my_event", "with ts", metadata=metadata)
	ep.publish(broker_topic, my_event)

	ep.shutdown()

@TEST-END-FILE
