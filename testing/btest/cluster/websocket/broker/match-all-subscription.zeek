# @TEST-DOC: Test a match-all subscription (topic array [""]) with Broker. Regression test for #5366, previously the manager would crash on LogCreate, LogWrite and IdentifierUpdate messages.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_LOGGER1_PORT
# @TEST-PORT: BROKER_LOGGER2_PORT
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
#
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run logger-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger-1 zeek -b ../logger.zeek"
# @TEST-EXEC: btest-bg-run logger-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger-2 zeek -b ../logger.zeek"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v -e "Error reading HTTP request line" -e "PEER_UNAVAILABLE"' btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./logger-1/.stdout
# @TEST-EXEC: btest-diff ./logger-2/.stdout
# @TEST-EXEC: btest-diff ./client/.stdout
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE common.zeek
@load frameworks/cluster/experimental
redef Broker::disable_ssl = T;

redef Log::default_rotation_interval = 0sec;

module Test;

export {
	# Created at runtime once all clients are connected
	# to trigger LogCreate broker messages.
	redef enum Log::ID += { LOG };

	type Info: record {
		msg: string &log;
	};

	# Updated with Broker::publish_id() to the number
	# of ws_added by the manager.
	global ws_added = 0;
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="ws"]);
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common

global ping: event(msg: string, c: count) &is_used;

global ping_count = 0;

global ws_added = 0;
global ws_lost = 0;

event Cluster::Experimental::cluster_started()
	{
	print "cluster_started";
	# Only start listening on the WebSocket port when the loggers
	# have connected.
	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
	]);
	}

event send_ping()
	{
	++ping_count;
	print fmt("%s: sending ping %s", current_time(), ping_count);
	Cluster::publish("/test/pings/", ping, "from-manager", ping_count);
	if ( ping_count < 3 )
		{
		event send_ping();
		}
	}

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	++ws_added;
	local msg = fmt("%s: Cluster::websocket_client_added %s %s", current_time(), ws_added, subscriptions);
	print msg;

	# Writing to the log writer will initialize it and then also trigger
	# WriterFrontend::Init() -> Manager::PublishLogCreate() for the loggers
	# as well as sending LogWrite messages.
	Log::write(Test::LOG, [$msg=msg]);
	Log::flush(Test::LOG);
	Broker::flush_logs();

	# Update the Test::ws_added identifier and publish it to other nodes.
	Test::ws_added = ws_added;
	Broker::publish_id(Cluster::logger_topic, "Test::ws_added");

	if ( ws_added == 3 )
		event send_ping();
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++ws_lost;
	print fmt("%s: Cluster::websocket_client_lost %s", current_time(), ws_lost);

	if ( ws_lost == 3 )
		{
		print current_time(), "terminate()";
		terminate();
		}
	}
# @TEST-END-FILE

# @TEST-START-FILE logger.zeek
@load ./common

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}

event zeek_done()
	{
	print "Test::ws_added", Test::ws_added;
	}
# @TEST-END-FILE logger.zeek


# @TEST-START-FILE client.py
import wstest

def run(ws_url):
    with (
        wstest.connect("ws1", ws_url) as tc1,
        wstest.connect("ws2", ws_url) as tc2,
        wstest.connect("ws3", ws_url) as tc3,
    ):
        clients = [tc1, tc2, tc3]
        print("Connected!")
        ids = set()
        for tc in clients:
            ack = tc.hello_v1([""])
            ids.add(ack["endpoint"])

        # The manager should send 3 pings in a row, receive them all.
        wstest.recv_until_timeout(clients, timeout=0.5)

if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
