# @TEST-DOC: Select WebSocket event serializers, exchange events, and reject a malformed binary frame.
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
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: python3 client.py
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global client_count = 0;
global lost_client_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/test/serialized");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

event ping(msg: string, n: count) &is_used
	{
	print fmt("got ping: %s, %s", msg, n);
	local e = Cluster::make_event(pong, msg, n);
	Cluster::publish("/test/serialized", e);
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++client_count;
	if ( client_count == 2 )
		{
		local e = Cluster::make_event(ping, "binary serializer", client_count);
		Cluster::publish("/test/serialized", e);
		}
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost_client_count;
	if ( lost_client_count == 2 )
		terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import json
import os
import struct

import wstest
from websockets.sync.client import connect

port = os.environ["WEBSOCKET_PORT"].split("/")[0]
url = f"ws://127.0.0.1:{port}/v1/messages"
topic = "/test/serialized"
topic_bytes = topic.encode("utf-8")


def make_frame(payload, frame_topic=topic_bytes):
    return struct.pack("!I", len(frame_topic)) + frame_topic + payload


def read_frame(frame):
    assert isinstance(frame, bytes)
    assert len(frame) >= 4
    topic_size = struct.unpack("!I", frame[:4])[0]
    assert topic_size <= len(frame) - 4
    return frame[4 : 4 + topic_size].decode("utf-8"), frame[4 + topic_size :]


def run(client_url):
    with connect(client_url) as ws:
        error = json.loads(ws.recv(timeout=5.0))
        assert error["type"] == "error", error
        assert error["code"] == "missing_serializer", error

    with connect(client_url, additional_headers={"X-Zeek-Event-Serializer": "unknown"}) as ws:
        error = json.loads(ws.recv(timeout=5.0))
        assert error["type"] == "error", error
        assert error["code"] == "unsupported_serializer", error

    with connect(client_url, additional_headers={"X-Zeek-Event-Serializer": "broker-json-v1"}) as ws:
        ws.send(json.dumps([topic]))
        ack = json.loads(ws.recv(timeout=5.0))
        assert ack["type"] == "ack", ack
        assert ack["serializer"] == "broker-json-v1", ack

        event = wstest.build_event_v1(topic, "ping", ["json serializer", 1])
        payload = json.dumps({"@data-type": event["@data-type"], "data": event["data"]}).encode()
        ws.send(make_frame(payload))

        received_topic, received_payload = read_frame(ws.recv(timeout=5.0))
        assert received_topic == topic, received_topic
        received_event = json.loads(received_payload)["data"][2]["data"]
        assert received_event[0]["data"] == "pong", received_event
        assert received_event[1]["data"][0]["data"] == "json serializer", received_event

        ws.send(make_frame(payload, b"<$>"))
        error = json.loads(ws.recv(timeout=5.0))
        assert error["type"] == "error", error

    with connect(client_url, additional_headers={"x-zeek-event-serializer": "broker-bin-v1"}) as ws:
        ws.send(json.dumps([topic]))
        ack = json.loads(ws.recv(timeout=5.0))
        assert ack["type"] == "ack", ack
        assert ack["serializer"] == "broker-bin-v1", ack

        received_topic, received_payload = read_frame(ws.recv(timeout=5.0))
        assert received_topic == topic, received_topic
        assert received_payload, "expected serialized event bytes"

        ws.send(make_frame(received_payload))
        response_topic, response_payload = read_frame(ws.recv(timeout=5.0))
        assert response_topic == topic, response_topic
        assert response_payload and response_payload != received_payload

        ws.send(make_frame(b"\x00"))
        error = json.loads(ws.recv(timeout=5.0))
        assert error["type"] == "error", error

        ws.send(b"\x00")
        error = json.loads(ws.recv(timeout=5.0))
        assert error["type"] == "error", error


if __name__ == "__main__":
    wstest.main(run, url)
# @TEST-END-FILE
