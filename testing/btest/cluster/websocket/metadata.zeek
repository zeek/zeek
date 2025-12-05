# @TEST-DOC: Run a single node cluster (manager) with a websocket server and have a single client connect to check the metadata it receives.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
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
# @TEST-EXEC: btest-bg-run manager-no-metadata "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run client-no-metadata "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager-no-metadata/out
# @TEST-EXEC: btest-diff ./manager-no-metadata/.stderr
# @TEST-EXEC: btest-diff ./client-no-metadata/out
# @TEST-EXEC: btest-diff ./client-no-metadata/.stderr
#
# @TEST-EXEC: btest-bg-run manager-metadata "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek EventMetadata::add_network_timestamp=T >out"
# @TEST-EXEC: btest-bg-run client-metadata "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager-metadata/out
# @TEST-EXEC: btest-diff ./manager-metadata/.stderr
# @TEST-EXEC: btest-diff ./client-metadata/out
# @TEST-EXEC: btest-diff ./client-metadata/.stderr
#
# @TEST-EXEC: btest-bg-run manager-metadata-from-client "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek EventMetadata::add_network_timestamp=T >out"
# @TEST-EXEC: btest-bg-run client-metadata-from-client "NETWORK_TIMESTAMP=1970-01-01T01:42:42 python3 ../client.py >out"

# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager-metadata-from-client/out
# @TEST-EXEC: btest-diff ./manager-metadata-from-client/.stderr
# @TEST-EXEC: btest-diff ./client-metadata-from-client/out
# @TEST-EXEC: btest-diff ./client-metadata-from-client/.stderr


# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

redef allow_network_time_forward = F;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	set_network_time(double_to_time(4711.0));

	Cluster::subscribe("/test/pings/");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
	}

event ping(msg: string, n: count) &is_used
	{
	print fmt("ping: %s, %s (metadata=%s), sending pong...", msg, n, EventMetadata::current_all());
	Cluster::publish("/test/pongs/", pong, msg + " " + msg, n + n);
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
import os
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url) as c:
        print("Connected!")
        ack = c.hello_v1(["/test/pongs/"])
        assert "type" in ack
        assert ack["type"] == "ack"
        assert "endpoint" in ack
        assert "version" in ack

        ack["endpoint"] = "endpoint"
        ack["version"] = "endpoint"
        print("ack", ack)
        ping = wstest.build_event_v1("/test/pings/", "ping", ["fourty-two", 42])

        if ts_str := os.environ.get("NETWORK_TIMESTAMP"):
            # Sneak timestamp metadata into the ping if the env variable is set
            ping["data"][2]["data"] += [{
                "@data-type": "vector",
                "data": [{
                    "@data-type": "vector", "data": [
                        {"@data-type": "count", "data": 1},
                        {"@data-type": "timestamp", "data": ts_str}
                    ],
                }]
            }]

        print("ping", ping)
        c.send_json(ping)
        pong = c.recv_json()
        print("pong", pong)

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
