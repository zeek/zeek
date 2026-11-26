# @TEST-DOC: Validate that one can control the maximum number of concurrent WebSocket connections.
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
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b %INPUT common.zeek"
# @TEST-EXEC: python3 client.py
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-START-FILE client.py
import time
import re

import websockets

import wstest


def get_max_connections() -> int:
    with open("max-connections.zeek") as f:
        m = re.search(r"MAX_CONNECTIONS = (\d+)", f.read())
        return int(m.group(1))


def connect_retry(name):
    for _ in range(wstest.MAIN_TRIES):
        try:
            return wstest.connect(name)
        except:
            time.sleep(wstest.MAIN_SLEEP)

    assert False, "failed to connect"


# Block until we can connect to the endpoint. We use a bogus context manager
# here since a `TestClient` cannot be closed explicitly, but we need to do that
# to not count against the limit.
with connect_retry("ready") as _:
    ...

max_connections = get_max_connections()
# We cannot run with `max_connections=0` since that would
# not allow doing the readiness check above.
assert max_connections > 0

# We can start up to `max_connections` clients.
within_limit = [connect_retry("foo") for _ in range(max_connections)]

# Any more clients cannot connect.
try:
    wstest.connect("foo")
    assert False, "should never reach here"
except (OSError, websockets.exceptions.WebSocketException):
    ...
# @TEST-END-FILE

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap
redef exit_only_after_terminate = T;

event zeek_init()
	{
	Cluster::listen_websocket([
		$listen_addr=127.0.0.1,
		$listen_port=to_port(getenv("WEBSOCKET_PORT")),
		$max_connections=MAX_CONNECTIONS,
	]);
	}
# @TEST-END-FILE

const MAX_CONNECTIONS = 1;

# @TEST-START-NEXT
const MAX_CONNECTIONS = 2;

# @TEST-START-NEXT
# Use a small upper limit to avoid allocating too many fds which could run into
# system-dependent limits.
const MAX_CONNECTIONS = 3;
