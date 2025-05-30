# @TEST-DOC: Send subscriptions and events without waiting for pong, should be okay, the websocket server will queue this a bit.
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

type Item: record {
    msg: string;
    n: count;
};

global queue: vector of Item;

function is_ready(): bool
	{
	return added == 2;
	}

function drain_if_ready()
	{
	if ( is_ready() && |queue| > 0 )
		{
		for ( _, item in queue )
			event ping(item$msg, item$n);

		delete queue;
		}
	}

event ping(msg: string, n: count) &is_used
	{
	# Queue the pings if we haven't seen both clients yet.
	if ( ! is_ready() )
		{
		queue += Item($msg=msg, $n=n);
		return;
		}

	++ping_count;
	print fmt("B got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, "my-message", ping_count);
	Cluster::publish("/test/clients", e);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++added;
	print "A Cluster::websocket_client_added", subscriptions;

	drain_if_ready();
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print "C Cluster::websocket_client_lost";
	if ( lost == 2 )
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
            clients = [ws1, ws2]
            print("Connected!")
            # Send subscriptions
            for c, ws in enumerate(clients, 1):
                client_topic = f"/test/client-{c}"
                ws.send(json.dumps([topic, client_topic]))

            for i in range(5):
                for c, ws in enumerate(clients, 1):
                    print(f"Sending ping {i} - ws{c}")
                    ws.send(json.dumps(make_ping(i, f"ws{c}")))

            for c, ws in enumerate(clients, 1):
                print(f"Receiving ack - ws{c}")
                ack = json.loads(ws.recv())
                assert "type" in ack
                assert ack["type"] == "ack"
                assert "endpoint" in ack
                assert "version" in ack

            for i in range(10):
                for c, ws in enumerate(clients, 1):
                    print(f"Receiving pong {i} - ws{c}")
                    pong = json.loads(ws.recv())
                    assert pong["@data-type"] == "vector"
                    ev = pong["data"][2]["data"]
                    print("topic", pong["topic"], "event name", ev[0]["data"], "args", ev[1]["data"])

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
