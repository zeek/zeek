# @TEST-DOC: Suspend pcap processing on a single-node worker, wait for a WebSocket client, resume processing and publish all new_connection() events on test.conns.{uid}
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run worker "zeek -r $TRACES/wikipedia.trace -b %INPUT"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py"
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff worker/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff client/.stdout

global my_new_connection: event(uid: string, c: count);

event zeek_init()
	{
	print network_time(), "zeek_init: suspend_processing()";
	suspend_processing();
	}

event zeek_init() &priority=-5
	{
	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT"))
	]);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print fmt("%s: Cluster::websocket_client_added %s", network_time(), subscriptions);
	continue_processing();
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	print fmt("%s: Cluster::websocket_client_lost: %s, %s", network_time(), code, reason);
	terminate();
	}

event network_time_init()
	{
	print network_time(), "network_time_init";
	}

global conns = 0;

event new_connection(c: connection)
	{
	++conns;
	print network_time(), "new_connection", c$uid, conns;
	Cluster::publish(fmt("test.conns.%s", c$uid), my_new_connection, c$uid, conns);
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done", path;
	Cluster::publish("test.finish", Pcap::file_done, path);
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}

# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url) as tc:
        print("Connected!")
        tc.hello_v1(["test."])

        while True:
            try:
                msg = tc.recv_json()
                ev = msg["data"][2]["data"][0]["data"]
                args = msg["data"][2]["data"][1]["data"]
                print(msg["topic"], ev, [a["data"] for a in args])
                if ev == "Pcap::file_done":
                    break;
            except wstest.ConnectionClosedOK:
                print("Connection closed OK")
                break

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
