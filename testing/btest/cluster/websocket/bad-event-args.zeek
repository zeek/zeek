# @TEST-DOC: A WebSocket client sending invalid data for an event.
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

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/zeek/event/my_topic");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

event ping(msg: string, n: count) &is_used
	{
	print fmt("got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, msg, n);
	Cluster::publish("/zeek/event/my_topic", e);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	print "Cluster::websocket_client_lost";
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import json, os, time
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'ws://127.0.0.1:{ws_port}/v1/messages/json'
topic = '/zeek/event/my_topic'

def make_ping(event_args):
    return {
        "type": "data-message",
        "topic": topic,
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {"@data-type": "vector", "data": [
                { "@data-type": "string", "data": "ping"},  # Event name
                { "@data-type": "vector", "data": event_args },
            ], },
        ],
    }

def run(ws_url):
    with connect(ws_url) as ws:
        print("Connected!")
        # Send subscriptions
        ws.send(json.dumps([topic]))
        ack = json.loads(ws.recv())
        assert "type" in ack
        assert ack["type"] == "ack"
        assert "endpoint" in ack
        assert "version" in ack

        ws.send(json.dumps(make_ping(42)))
        err1 = json.loads(ws.recv())
        print("err1", err1)
        ws.send(json.dumps(make_ping([{"@data-type": "string", "data": "Hello"}])))
        err2 = json.loads(ws.recv())
        print("err2", err2)
        ws.send(json.dumps(make_ping([{"@data-type": "count", "data": 42}, {"@data-type": "string", "data": "Hello"}])))
        err3 = json.loads(ws.recv())
        print("err3", err3)

        # This should be good ping(string, count)
        ws.send(json.dumps(make_ping([{"@data-type": "string", "data": "Hello"}, {"@data-type": "count", "data": 42}])))
        pong = json.loads(ws.recv())
        name, args, _ = pong["data"][2]["data"]
        print("pong", name, args)

        # This one fails again
        ws.send(json.dumps(make_ping([{"@data-type": "money", "data": 0}])))
        err4 = json.loads(ws.recv())
        print("err4", err4)

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
