# @TEST-DOC: Test visibility of WebSockets client's messages when the Broker cluster backend is used.
#
# Worker peers with a manager, manager opens a websocket port, three websocket clients connect.
#
# Expectations:
#
# * ping events from one websocket client are received by manager, worker, and the other websocket clients
# * pong events from manager and worker are received by all websocket clients and worker or manager
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: zeek -b --parse-only worker.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v "Error reading HTTP request line"' btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v PEER_UNAVAILABLE' btest-diff ./worker-1/.stderr
# @TEST-EXEC: btest-diff ./client/.stdout
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $manager="manager"],
};
# @TEST-END-FILE

# @TEST-START-FILE common.zeek
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

global ping_count = 0;

redef Broker::disable_ssl = T;

event zeek_init()
	{
	Cluster::subscribe("/test/pings/");
	}

event pong(msg: string, n: count) &is_used
	{
	print fmt("%s: got pong: %s, %s", current_time(), msg, n);
	}

event ping(msg: string, n: count) &is_used
	{
        ++ping_count;
	print fmt("%s: got ping: %s, %s", current_time(), msg, n);

	local reply_msg = fmt("%s reply for ping(%s, %s)", Cluster::node, msg, n);
	if ( (msg == "to-manager" && Cluster::local_node_type() == Cluster::MANAGER) ||
	     (msg == "to-worker" && Cluster::local_node_type() == Cluster::WORKER) )
		Cluster::publish("/test/pings/", pong, reply_msg, ping_count);
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string)
	{
	print fmt("%s: Cluster::node_up %s", current_time(), name);

	# Delay listening on WebSocket clients until worker-1 is around.
	if ( name == "worker-1" )
		Cluster::listen_websocket([
			$listen_addr=127.0.0.1,
			$listen_port=to_port(getenv("WEBSOCKET_PORT"))
		]);
	}

global added = 0;
global lost = 0;

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
		print fmt("%s: terminate()", current_time());
		terminate();
		}
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event Cluster::node_up(name: string, id: string)
	{
	print fmt("%s: Cluster::node_up %s", current_time(), name);
	}

event Cluster::node_down(name: string, id: string)
	{
	print fmt("%s: Cluster::node_down %s", current_time(), name);
	terminate();
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

        print("unique ids", len(ids))

        for i in range(1, 4):
            msg = "to-manager" if i % 2 == 0 else "to-worker"
            tc1.send_json(wstest.build_event_v1("/test/pings/", "ping", [msg, 100 + i]))
            wstest.recv_until_timeout(clients, desc=f"tc1 - ping {i}")

            tc2.send_json(wstest.build_event_v1("/test/pings/", "ping", [msg, 200 + i]))
            wstest.recv_until_timeout(clients, desc=f"tc2 - ping {i}")

            tc3.send_json(wstest.build_event_v1("/test/pings/", "ping", [msg, 300 + i]))
            wstest.recv_until_timeout(clients, desc=f"tc3 - ping {i}")


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
