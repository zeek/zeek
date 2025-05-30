# @TEST-DOC: Test visibility of endpoint messages at websocket clients.
#
# Manager opens a websocket port, waits for three clients, each of the clients
# sends 3 ping messages. The manager observes them all.
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
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v "Error reading HTTP request line"' btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/.stdout
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
};
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;

global ping: event(msg: string, c: count) &is_used;

global ping_count = 0;

redef Broker::disable_ssl = T;

global added = 0;
global lost = 0;

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
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print fmt("%s: Cluster::websocket_client_added %s %s", current_time(), added, subscriptions);
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print fmt("%s: Cluster::websocket_client_lost %s", current_time(), lost);
	if ( lost == 3 )
		{
		print current_time(), "terminate()";
		terminate();
		}
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with (
        wstest.connect("ws1", ws_url) as tc1,
        wstest.connect("ws2", ws_url) as tc2,
        wstest.connect("ws3", ws_url) as tc3,
    ):
        clients = [tc1, tc2, tc3]
        print("Connected!")
        ids = set()
        for tc in clients:
            ack = tc.hello_v1(["/test/pings/"])
            ids.add(ack["endpoint"])

            # Send 3x3 pings to the manager and consume the messages
            # to the clients as well.
        for i in range(1, 4):
           tc1.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"ws1-{i}", 100 + i]))
           wstest.recv_until_timeout(clients)
           tc2.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"ws2-{i}", 200 + i]))
           wstest.recv_until_timeout(clients)
           tc3.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"ws3-{i}", 300 + i]))
           wstest.recv_until_timeout(clients)


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
