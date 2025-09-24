# @TEST-DOC: Regression test for #4420. Clients publish fast and Zeek terminates after receiving 1000 events. Previously this would result in a hang at Zeek shutdown.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/single-node.zeek zeromq-single-node.zeek
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: sort ./manager/out > ./manager/out.sorted
# @TEST-EXEC: btest-diff ./manager/out.sorted
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load zeromq-single-node

redef exit_only_after_terminate = T;

# Force dispatcher queue being full quickly!
redef Cluster::default_websocket_max_event_queue_size = 1;

global ping_count = 0;
global ping: event(msg: string, c: count) &is_used;

global clients: set[string] = set();

event ping(client: string, n: count) &is_used
	{
        ++ping_count;
        add clients[client];

        if ( ping_count == 1000 )
            {
            print fmt("D got 1000 pings from %s clients, terminating", |clients|);
            terminate();
            }
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "B Cluster::websocket_client_added", subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	print "E Cluster::websocket_client_lost";
	}

event zeek_init()
	{
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	Cluster::subscribe("/test/pings/");
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import websockets.exceptions

import wstest

wstest.monkey_patch_close_socket()

def run(ws_url):
    with (
        wstest.connect("ws1", ws_url) as tc1,
        wstest.connect("ws2", ws_url) as tc2,
        wstest.connect("ws3", ws_url) as tc3,
    ):
        clients = [tc1, tc2, tc3]
        for tc in clients:
            tc.hello_v1([])

        stop = False;
        i = 0

        saw_closed_ok = set()

        while len(saw_closed_ok) < 3:
            for idx, tc in enumerate(clients, 1):
                if idx in saw_closed_ok:  # Have seen a ConnectionClosedOK for this client?
                    continue

                try:
                    i += 1
                    tc.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"tc{idx}", i]))
                except websockets.exceptions.ConnectionClosedOK as e:
                    print("connection closed ok")
                    assert e.code == 1001, f"expected code 1001, got {e.code} - {e}"  # Remote going away
                    i -= 1
                    saw_closed_ok.add(idx)

        assert len(saw_closed_ok) == 3
        assert i >= 1000, f"expected to send at least 1000 events, only sent {i}"

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
