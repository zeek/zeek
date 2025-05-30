# @TEST-DOC: Clients sends broken subscription arrays
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

# # @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/zeek/event/my_topic");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

global added = 0;
global lost = 0;

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print "Cluster::websocket_client_added", added, subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print "Cluster::websocket_client_lost", lost;
	if ( lost == 4 )
		terminate();
	}
# # @TEST-END-FILE


# @TEST-START-FILE client.py
import json, os, time
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'ws://127.0.0.1:{ws_port}/v1/messages/json'
topic = '/zeek/event/my_topic'

def run(ws_url):
    with connect(ws_url) as ws:
        ws.send('["broken", "brrr')
        err = json.loads(ws.recv())
        print("broken array response", err)

    with connect(ws_url) as ws:
        ws.send('[1, 2]')
        err = json.loads(ws.recv())
        print("non string error", err)

    with connect(ws_url) as ws:
        ws.send('[1, "/my_topic"]')
        err = json.loads(ws.recv())
        print("mix error", err)

    # This should work - maybe duplicate isn't great, but good for testing.
    with connect(ws_url) as ws:
        ws.send('["/topic/good", "/duplicate", "/duplicate", "/is/okay"]')
        ack = json.loads(ws.recv())
        print("ack", ack["type"] == "ack")

def main():
    for _ in range(100):
        try:
            run(ws_url)
            break
        except ConnectionRefusedError:
            time.sleep(0.1)

if __name__ == "__main__":
    main()
# @TEST-END-FILE
