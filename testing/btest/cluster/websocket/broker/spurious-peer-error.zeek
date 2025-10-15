# @TEST-DOC: Ensure errors from the Broker core are not sent to WebSocket clients.
#
# Previously, when Broker::peer() from a Zeek node to another node failed,
# the BrokerWebSocketShim would "see" these errors on the errors topic and
# forward them to any connected WebSocket client.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: python3 client.py > client.out
#
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: btest-diff ./manager/.stdout
# Check for peering error
# @TEST-EXEC: grep 'PEER_UNAVAILABLE' ./manager/.stderr
# @TEST-EXEC: btest-diff client.out

# @TEST-START-FILE manager.zeek
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;

global ping: event(msg: string, c: count) &is_used;

global ping_count = 0;

redef Broker::disable_ssl = T;

event zeek_init()
	{
	Cluster::subscribe("/test/pings/");

	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
	]);
	}

event ping(msg: string, n: count) &is_used
	{
        ++ping_count;
	print fmt("%s: got ping: %s, %s", current_time(), msg, n);
	Cluster::publish("/test/pings/reply", ping, msg, n);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print fmt("%s: Cluster::websocket_client_added %s", current_time(), subscriptions);

	Broker::peer("127.0.0.1", 21/tcp);
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	print fmt("%s: Cluster::websocket_client_lost", current_time());
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url) as tc1:
        print("Connected!")
        ack = tc1.hello_v1(["/test/pings/"])

        # Send 3 pings!
        for i in range(1, 4):
           tc1.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"ws1-{i}", 100 + i]))
           wstest.recv_until_timeout([tc1])


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
