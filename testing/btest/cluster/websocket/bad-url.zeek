# @TEST-DOC: Run a single node cluster (manager) with a websocket server and have a single client connect.
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
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

global ping_count = 0;

global ping: event(msg: string, c: count) &is_used;
global pong: event(msg: string, c: count) &is_used;

event zeek_init()
	{
	Cluster::subscribe("/zeek/event/my_topic");
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT"))]);
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
import json, os, time
import websockets.exceptions
from websockets.sync.client import connect

ws_port = os.environ['WEBSOCKET_PORT'].split('/')[0]
ws_prefix = f'ws://127.0.0.1:{ws_port}'
topic = '/zeek/event/my_topic'


def run(ws_prefix):
    with connect(ws_prefix + '/v1/messages/json') as ws_good:
        print('Connected ws_good!')
        with connect(ws_prefix + '/v0/messages/json') as ws_bad:
            print('Connected ws_bad!')
            try:
                err = json.loads(ws_bad.recv())
            except websockets.exceptions.ConnectionClosedError as e:
                pass

            print('Error for ws_bad', err)

        ws_good.send(json.dumps(['hello-good']))
        ack = json.loads(ws_good.recv())
        assert 'type' in ack
        assert ack['type'] == 'ack'

def main():
    for _ in range(100):
        try:
            run(ws_prefix)
            break
        except ConnectionRefusedError:
            time.sleep(0.1)

if __name__ == '__main__':
    main()
# @TEST-END-FILE
