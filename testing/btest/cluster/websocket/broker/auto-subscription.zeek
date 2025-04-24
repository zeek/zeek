# @TEST-DOC: Test that publishing events to a WebSocket client's auto topic works.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py"
#
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/.stdout
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
};
# @TEST-END-FILE
#
# @TEST-START-FILE manager.zeek
redef exit_only_after_terminate = T;

redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;
redef Broker::disable_ssl = T;

global ws_client_topic = "";

event zeek_init()
	{
	Cluster::subscribe("/test/pings");
	Cluster::listen_websocket([$listen_host="127.0.0.1", $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

global pong: event(c: count) &is_used;

event ping(c: count) &is_used
	{
	print "ping", c;
	# Reply with a pong on the WebSocket client's auto topic.
	Cluster::publish(ws_client_topic, pong, c);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	ws_client_topic = Cluster::websocket_client_topic(info$id);
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo)
	{
	print "Cluster::websocket_client_lost";
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url) as tc:
        print("connected")
        tc.send_json([])  # Send no subscriptions
        ack = tc.recv_json()
        print("got ack")
        assert ack.get("type") == "ack", f"{ack}"

        # Send a ping to the manager.
        tc.send_json(wstest.build_event_v1("/test/pings/", "ping", [42]))
        pong = tc.recv_json(timeout=3)
        topic, event = pong["topic"], pong["data"][2]["data"][0:2]
        topic_parts = topic.split("/")
        print("ack[endpoint] in topic_parts", ack["endpoint"] in topic_parts)
        print("event", event)


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
