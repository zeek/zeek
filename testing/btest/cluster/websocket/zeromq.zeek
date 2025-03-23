# @TEST-DOC: Test WebSockets clients when the ZeroMQ cluster backend is enabled.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek worker.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./worker-1/out
# @TEST-EXEC: btest-diff ./worker-1/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

@TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

@TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;

redef Broker::disable_ssl = T;

global ping_count = 0;

event zeek_init()
	{
	Cluster::subscribe("/test/pings/");
	}

event Cluster::node_up(name: string, id: string)
	{
	print "Cluster::node_up", name;

	# Delay listening on WebSocket clients until worker-1 is around.
	if ( name == "worker-1" )
		Cluster::listen_websocket([
			$listen_host="127.0.0.1",
			$listen_port=to_port(getenv("WEBSOCKET_PORT"))
		]);
	}

event ping(msg: string, n: count) &is_used
	{
        ++ping_count;
	print fmt("got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, fmt("orig_msg=%s", msg), ping_count);
	Cluster::publish("/test/clients", e);
	}

global added = 0;
global lost = 0;

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print "Cluster::websocket_client_added", added, subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo)
	{
	++lost;
	print "Cluster::websocket_client_lost", lost;
	if ( lost == 3 )
		terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

event zeek_init()
	{
	Cluster::subscribe("/test/pings/");
	}

event Cluster::node_up(name: string, id: string)
	{
	print "Cluster::node_up", name;
	}

event Cluster::node_down(name: string, id: string)
	{
	print "Cluster::node_up", name;
	terminate();
	}

event ping(msg: string, n: count)
	{
	print fmt("got ping: %s, %s", msg, n);
	}
# @TEST-END-FILE


@TEST-START-FILE client.py
import json, os, time
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'ws://127.0.0.1:{ws_port}/v1/messages/json'

def make_ping(topic, c):
    return {
        "type": "data-message",
        "topic": topic + str(c),
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {"@data-type": "vector", "data": [
                { "@data-type": "string", "data": "ping"},  # Event name
                { "@data-type": "vector", "data": [  # event args
                    {"@data-type": "string", "data": f"python-websocket-client"},
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
                for i, c in enumerate(clients, 1):
                    c.send(json.dumps([f"/test/ws/{i}", "/test/pings/"]))
                    ack = json.loads(c.recv())
                    assert "type" in ack, repr(ack)
                    assert ack["type"] == "ack"
                    assert "endpoint" in ack, repr(ack)
                    assert "version" in ack
                    ids.add(ack["endpoint"])

                print("unique ids", len(ids))
                ws1.send(json.dumps(make_ping("/test/pings/", 42)))

                # Client 2 and client 3 receive the ping from client 1, client 1 gets a timeout.
                for name, ws in [("ws1", ws1), ("ws2", ws2), ("ws3", ws3)]:
                    try:
                        data = json.loads(ws.recv(timeout=0.1))
                        ev = data["data"][2]["data"]
                        print(name, "ev: topic", data["topic"], "event name", ev[0]["data"], "args", ev[1]["data"])
                    except TimeoutError:
                        print(name, "timeout")

def main():
    for _ in range(100):
        try:
            run(ws_url)
            break
        except ConnectionRefusedError:
            time.sleep(0.1)

if __name__ == "__main__":
    main()
@TEST-END-FILE
