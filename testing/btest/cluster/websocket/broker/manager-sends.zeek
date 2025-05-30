# @TEST-DOC: Test visibility of endpoint messages at websocket clients.
#
# Manager opens a websocket port, waits for three clients, sends 3 ping messages,
# the clients observe the manager's messages.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
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
	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
	]);
	}

event send_ping()
	{
	++ping_count;
	print fmt("%s: sending ping %s", current_time(), ping_count);
	Cluster::publish("/test/pings/", ping, "from-manager", ping_count);
	if ( ping_count < 3 )
		event send_ping();
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print fmt("%s: Cluster::websocket_client_added %s %s", current_time(), added, subscriptions);
	if ( added == 3 )
		event send_ping();
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

        # The manager should send 3 pings in a row, receive them all.
        wstest.recv_until_timeout(clients, timeout=0.5)


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
