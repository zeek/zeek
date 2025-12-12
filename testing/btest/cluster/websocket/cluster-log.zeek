# @TEST-DOC: Test websocket clients appearing in cluster.log
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
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: zeek-cut node message <  ./manager/cluster.log | sed -r "s/client '.+' /client <nodeid> /g" | sed -r "s/:[0-9]+/:<port>/g" > ./manager/cluster.log.cannonified
# @TEST-EXEC: btest-diff ./manager/cluster.log.cannonified
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

# Have the manager create cluster.log
redef Log::enable_local_logging = T;
redef Log::default_rotation_interval = 0sec;

global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/test/manager");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
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

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print "Cluster::websocket_client_lost", lost;
	if ( lost == 3 )
		terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import json, os, time
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_url = f'ws://127.0.0.1:{ws_port}/v1/messages/json'

def run(ws_url):
    with connect(ws_url, additional_headers={"X-Application-Name": "super-duper-app"}) as ws1:
        with connect(ws_url) as ws2:
            with connect(ws_url, additional_headers={"X-Application-Name": "super-duper-app"}) as ws3:
                 clients = [ws1, ws2, ws3]
                 print("Connected!")
                 ids = set()
                 for i, c in enumerate(clients, 1):
                     c.send(json.dumps([f"/topic/ws/{i}", "/topic/ws/all"]))
                     ack = json.loads(c.recv())
                     assert "type" in ack, repr(ack)
                     assert ack["type"] == "ack"
                     assert "endpoint" in ack, repr(ack)
                     assert "version" in ack
                     ids.add(ack["endpoint"])

                 print("unique ids", len(ids))

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
