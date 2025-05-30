# @TEST-DOC: Ensure the websocket_client_lost() event contains code and reason. This starts two WebSocket client that aren't replying to PING frames.
#
# @TEST-REQUIRES: python3 -c 'import websockets.sync'
#
# @TEST-PORT: WEBSOCKET_PORT
#
# @TEST-EXEC: cp $FILES/ws/wstest.py .
# @TEST-EXEC: zeek -b --parse-only manager.zeek
# @TEST-EXEC: python3 -m py_compile client.py
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run client "python3 ../client.py >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/out
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: zeek-cut message <  ./manager/cluster.log | sed -r "s/client '.+' /client <nodeid> /g" | sed -r "s/:[0-9]+/:<port>/g" > ./manager/cluster.log.cannonified
# @TEST-EXEC: btest-diff ./manager/cluster.log.cannonified
# @TEST-EXEC: btest-diff ./client/out
# @TEST-EXEC: btest-diff ./client/.stderr

# @TEST-START-FILE manager.zeek
redef exit_only_after_terminate = T;

global lost = 0;

event Cluster::websocket_client_added(info: Cluster::EndpointInfo, subscriptions: string_vec)
	{
	print "Cluster::websocket_client_added", subscriptions;
	}

event Cluster::websocket_client_lost(info: Cluster::EndpointInfo, code: count, reason: string)
	{
	++lost;
	print "Cluster::websocket_client_lost", code, reason;
	if ( lost == 2 )
		terminate();
	}

event zeek_init()
	{
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=to_port(getenv("WEBSOCKET_PORT")), $ping_interval=1sec]);
	Cluster::subscribe("/test/pings/");
	}
# @TEST-END-FILE


# @TEST-START-FILE client.py
import json
import functools

import wstest

from websockets.sync.client import connect
from websockets.sync.client import ClientConnection
from websockets.frames import OP_PONG

class MyClientConnection(ClientConnection):
    """
    Custom Client class patching the protocol.send_frame() function
    to discard any PONG frames. The websocket library responds
    automatically to these in a thread and can't easily turn this off,
    but we want to test Zeek behavior when a client fails to respond
    with PONG frames quickly enough.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__orig_send_frame = self.protocol.send_frame
        def __my_send_frame(_self, frame):
            if frame.opcode != OP_PONG:
                self.__orig_send_frame(frame)

        self.protocol.send_frame = functools.partial(__my_send_frame, self.protocol)

def run(ws_url):
    with (
        connect(ws_url, create_connection=MyClientConnection) as c1,
        connect(ws_url, create_connection=MyClientConnection) as c2,
    ):
        c1.send(json.dumps([]))
        ack1 = json.loads(c1.recv())
        assert ack1["type"] == "ack", repr(ack1)

        c2.send(json.dumps([]))
        ack2 = json.loads(c2.recv())
        assert ack2["type"] == "ack", repr(ack2)

        try:
            c1.recv()
        except Exception as e:
            print(e)
        try:
            c2.recv()
        except Exception as e:
            print(e)


if __name__ == "__main__":
    wstest.main(run, wstest.WS4_URL_V1)
# @TEST-END-FILE
