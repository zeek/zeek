# @TEST-DOC: Run a single node cluster (manager) with a websocket server, have three clients connect.
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
# @TEST-EXEC: sort ./manager/out > ./manager/out.sorted
# @TEST-EXEC: btest-diff ./manager/out.sorted
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# # @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

global added = 0;
global lost = 0;

event ping(msg: string, n: count) &is_used
	{
        ++ping_count;
	print fmt("C got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, fmt("orig_msg=%s", msg), ping_count);
	Cluster::publish("/test/clients", e);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print "B Cluster::websocket_client_added", subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print "D Cluster::websocket_client_lost", lost;
	if ( lost == 3 )
		terminate();
}

# Extra testing output.
event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	if ( ! starts_with(topic, "/test") )
		return;

	print "A subscription", topic;
	}

event zeek_init()
	{
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	Cluster::subscribe("/test/manager");
	}
# # @TEST-END-FILE


# @TEST-START-FILE client.py
import json, os, time
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'ws://127.0.0.1:{ws_port}/v1/messages/json'
topic = '/test/clients'

def make_ping(c, who):
    return {
        "type": "data-message",
        "topic": "/test/manager",
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {"@data-type": "vector", "data": [
                { "@data-type": "string", "data": "ping"},  # Event name
                { "@data-type": "vector", "data": [  # event args
                    {"@data-type": "string", "data": who},
                    {"@data-type": "count", "data": c},
                ], },
            ], },
        ],
    }

def run(ws_url):
    with connect(ws_url) as ws1:
        with connect(ws_url) as ws2:
            with connect(ws_url) as ws3:
                 clients = [ws1, ws2, ws3]
                 print("Connected!")
                 ids = set()
                 for i, c in enumerate(clients):
                     client_topic = f"/test/client-{i}"
                     c.send(json.dumps([topic, client_topic]))

                 for c in clients:
                     ack = json.loads(c.recv())
                     assert "type" in ack, repr(ack)
                     assert ack["type"] == "ack"
                     assert "endpoint" in ack, repr(ack)
                     assert "version" in ack
                     ids.add(ack["endpoint"])

                 print("unique ids", len(ids))

                 for i in range(16):
                     c = clients[i % len(clients)]
                     name = f"ws{(i % len(clients)) + 1}"
                     print(name, "sending ping", i)
                     c.send(json.dumps(make_ping(i, name)))

                     print("receiving pong", i)
                     for c in clients:
                         pong = json.loads(c.recv())
                         ev = pong["data"][2]["data"]
                         print("ev: topic", pong["topic"], "event name", ev[0]["data"], "args", ev[1]["data"])

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
