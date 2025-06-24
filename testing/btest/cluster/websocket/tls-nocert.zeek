# @TEST-DOC: Run a single node cluster (manager) with a websocket server that has TLS enabled without certs, similar to the Broker::listen_websocket() default.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: python3 -c 'import websockets.asyncio'
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
# @TEST-EXEC: python3 client.py
#
# @TEST-EXEC: btest-bg-wait -k 1
# @TEST-EXEC: btest-diff ./manager/out

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/zeek/event/my_topic");

	# Enable encryption, but don't require authentication (and not even certificates).
	#
	# This is the old Broker::listen_websocket() default behavior.
	local tls_options = Cluster::WebSocketTLSOptions(
		$cert_file="",
		$key_file="",
		$ca_file="NONE",
		$ciphers="AECDH-AES256-SHA@SECLEVEL=0:AECDH-AES256-SHA:P-384",
	);

	local ws_server_options = Cluster::WebSocketServerOptions(
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
		$tls_options=tls_options,
	);

	Cluster::listen_websocket(ws_server_options);
	}

event ping(msg: string, n: count) &is_used
	{
	++ping_count;
	print fmt("got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, "my-message", ping_count);
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
import asyncio
import json
import os
import socket
import ssl
import time
from websockets.asyncio.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'wss://localhost:{ws_port}/v1/messages/json'
topic = '/zeek/event/my_topic'

# Make the websockets library use the custom server cert.
# https://stackoverflow.com/a/55856969
os.environ["SSL_CERT_FILE"] = "../localhost.crt"

def make_ping(c):
    return {
        "type": "data-message",
        "topic": topic,
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {"@data-type": "vector", "data": [
                { "@data-type": "string", "data": "ping"},  # Event name
                { "@data-type": "vector", "data": [  # event args
                    {"@data-type": "string", "data": "python-websocket-client"},
                    {"@data-type": "count", "data": c},
                ], },
            ], },
        ],
    }

async def run():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("AECDH-AES256-SHA@SECLEVEL=0:AECDH-AES256-SHA:P-384")
    async with connect(ws_url, family=socket.AF_INET, ssl=ctx) as ws:
        print("Connected!")
        # Send subscriptions
        await ws.send(json.dumps([topic]))
        ack = json.loads(await ws.recv())
        assert "type" in ack
        assert ack["type"] == "ack"
        assert "endpoint" in ack
        assert "version" in ack

        for i in range(5):
            print("Sending ping", i)
            await ws.send(json.dumps(make_ping(i)))
            print("Receiving pong", i)
            pong = json.loads(await ws.recv())
            assert pong["@data-type"] == "vector"
            ev = pong["data"][2]["data"]
            print("topic", pong["topic"], "event name", ev[0]["data"], "args", ev[1]["data"])

def main():
    for _ in range(100):
        try:
            asyncio.run(run())
            return
        except ConnectionRefusedError:
            time.sleep(0.1)

    raise RuntimeError("could not connect to Zeek endpoint")

if __name__ == "__main__":
    main()
# @TEST-END-FILE
