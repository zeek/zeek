# @TEST-DOC: Output cluster telemetry after working with a WebSocket client. The WebSocket client sends an X-Application-Name header. Also include debug metrics as histograms in the output.
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
# @TEST-EXEC: python3 client.py
#
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff ./manager/.stderr

# @TEST-START-FILE manager.zeek
@load base/frameworks/telemetry

@load ./zeromq-test-bootstrap

redef Cluster::Telemetry::core_metrics += {
	Cluster::Telemetry::VERBOSE,
	Cluster::Telemetry::DEBUG,
};

redef Cluster::Telemetry::websocket_metrics += {
	Cluster::Telemetry::VERBOSE,
	Cluster::Telemetry::DEBUG,
};

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
	if ( ping_count % 2 == 0)  # Reply every other ping.
		{
		Cluster::publish(fmt("/test/pings/%s", ping_count % 4), ping, msg, n);
		}

	++ping_count;

	if ( ping_count == expected_ping_count )
		terminate();
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	}

event zeek_done()
	{
	local ms = Telemetry::collect_metrics("zeek", "cluster_core_*");
	ms += Telemetry::collect_metrics("zeek", "cluster_websocket_*");
	print "zeek_cluster_* metrics", |ms|;
	for ( _, m in ms )
		print m$opts$prefix, m$opts$name, m$label_names, m$label_values, m$value;

	local hms = Telemetry::collect_histogram_metrics("zeek", "cluster_core_*");
	hms += Telemetry::collect_histogram_metrics("zeek", "cluster_websocket_*");

	print "zeek_cluster_* histogram metrics", |hms|;
	for ( _, hm in hms )
		print hm$opts$prefix, hm$opts$name, hm$label_names, hm$label_values, hm$values;
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with wstest.connect("ws1", ws_url, additional_headers={"X-Application-Name": "btest-python-client"}) as tc:
        tc.hello_v1(["/test/pings"])
        for i in range(0, 100):
            msg = f"ping {i}" + (i * 32 * "A")
            tc.send_json(wstest.build_event_v1(f"/test/pings/{i % 4}", "ping", [msg, i]))
            if i % 2 == 0:  # Wait for a reply for every other ping
                tc.recv_json()

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
