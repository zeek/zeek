# @TEST-DOC: Running a standalone Zeek process with a WebSocket server using ZeroMQ.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: ZEEK_WEBSOCKET_LISTEN_PORT
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: WEBSOCKET_PORT=${ZEEK_WEBSOCKET_LISTEN_PORT} python3 ./client.py > client.out
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff ./zeek/.stdout
# @TEST-EXEC: grep 'Running.*CLUSTER_BACKEND_ZEROMQ' ./zeek/.stderr
# @TEST-EXEC: btest-diff ./client.out

@load frameworks/cluster/websocket/server

# Redef snippet for running XPUB/XSUB on ephemeral ports.
@load base/utils/numbers
module Cluster::Backend::ZeroMQ;

global xpub_port = extract_count(getenv("XPUB_PORT"));
global xsub_port = extract_count(getenv("XSUB_PORT"));
redef listen_xsub_endpoint  = fmt("tcp://127.0.0.1:%s", xsub_port);
redef connect_xpub_endpoint  = listen_xsub_endpoint;
redef listen_xpub_endpoint  = fmt("tcp://127.0.0.1:%s", xpub_port);
redef connect_xsub_endpoint  = listen_xpub_endpoint;
# Redef snippet ===

event zeek_init()
	{
	Cluster::subscribe("/test/pings/");
	}

event ping(msg: string, n: count) &is_used
	{
	print n, msg;
	Cluster::publish("/test/pings/", ping, msg, n);
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

# @TEST-START-FILE client.py
import wstest
wstest.DEFAULT_RECV_TIMEOUT=5.0

def run(ws_url):
    with wstest.connect("ws1", ws_url) as tc:
        tc.hello_v1(["/test/pings/"])
        tc.send_json(wstest.build_event_v1("/test/pings/", "ping", ["ping", 42]))
        pong = tc.recv_json()
        print(pong)

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
