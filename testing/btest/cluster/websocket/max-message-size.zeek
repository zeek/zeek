# @TEST-DOC: A WebSocket message above max_message_size is closed with code 1009. A smaller message is accepted.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

event zeek_init()
	{
	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
		$max_message_size=64]);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	print fmt("Cluster::websocket_client_lost %s %s", code, reason);
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import json, os, time
import websockets.exceptions
from websockets.sync.client import connect

ws_port = os.environ["WEBSOCKET_PORT"].split("/")[0]
ws_url = f"ws://127.0.0.1:{ws_port}/v1/messages/json"
topic = "/zeek/event/my_topic"
limit = 64

def run(ws_url):
    with connect(ws_url, max_size=None) as ws:
        small = json.dumps([topic])
        assert len(small.encode()) <= limit
        ws.send(small)
        ack = json.loads(ws.recv())
        assert ack["type"] == "ack"
        print("small message accepted")

        ws.send("x" * (limit + 1))
        try:
            ws.recv()
        except websockets.exceptions.ConnectionClosed as e:
            print(f"large message closed {e.code}")
            assert e.code == 1009

def main():
    for _ in range(100):
        try:
            run(ws_url)
            return
        except ConnectionRefusedError:
            time.sleep(0.1)
    raise RuntimeError("manager did not accept a connection")

if __name__ == "__main__":
    main()
# @TEST-END-FILE
