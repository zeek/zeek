# @TEST-DOC: Connect with a WebSocket client, it sends 100 events and disconnects immediately. Ensure the manager sees all of them. Regression test for ZeroMQ discarding queued messages.
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
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/.stdout
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global expected_ping_count = 100;
global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/test/pings");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

event ping(msg: string, n: count) &is_used
	{
	++ping_count;
	print n, msg;

	if ( ping_count == expected_ping_count )
		terminate();
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url) as tc:
        tc.hello_v1([])
        for i in range(0, 100):
            tc.send_json(wstest.build_event_v1("/test/pings/", "ping", [f"ping {i}", i]))

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
