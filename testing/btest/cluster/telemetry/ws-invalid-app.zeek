# @TEST-DOC: Test a WebSocket client with an invalid X-Application-Name that is rejected.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: python3 client.py > client.out 2>&1
#
# @TEST-EXEC: btest-diff client.out

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap

global ping: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/test/pings");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

# terminate() on the first proper client connection.
event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import websockets.exceptions
import wstest

def run(ws_url):
    try:
        with wstest.connect("ws1", ws_url, additional_headers={"X-Application-Name": "!!invalid~~"}) as tc:
            print("connected")
            while True:
                err = tc.recv_json()
                print("recv", "code", err["code"], "context", err["context"])
    except websockets.exceptions.ConnectionClosedError as e:
        print("exception", "code", e.code, "reason", e.reason)

    # For terminating the Zeek server.
    with wstest.connect("ws2", ws_url) as tc:
        tc.hello_v1([])

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
