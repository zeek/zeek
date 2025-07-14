# @TEST-DOC: Test that publishing events to a WebSocket client's auto topic works.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: WEBSOCKET_PORT
#
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

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
};
# @TEST-END-FILE
#
# @TEST-START-FILE manager.zeek
redef exit_only_after_terminate = T;

redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;
redef Broker::disable_ssl = T;

event zeek_init()
	{
	Cluster::subscribe("/test/pings");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

global ping_count = 0;
const ping_count_expected = 32;

event ping(c: count) &is_used
	{
	++ping_count;
	print "got ping", c, ping_count;
	if ( ping_count == ping_count_expected )
	    terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    for i in range(32):
        with wstest.connect("ws1", ws_url) as tc:
            tc.send_json([])  # Send no subscriptions
            ack = tc.recv_json()
            assert ack.get("type") == "ack", f"{ack}"
            tc.send_json(wstest.build_event_v1("/test/pings/", "ping", [i + 1]))

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
