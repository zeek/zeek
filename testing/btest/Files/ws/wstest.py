"""
Testing library for WebSocket tests.

Usage in btests
===============

Add a TEST-EXEC line to make the library available in the test's directory:

    # @TEST-EXEC: cp ${FILES}/ws/wstest.py .

Then, in a Python file for the WebSocket client, do something like the
following to connect, subscribe to /test/topic and send a ping event.

    import wstest

    def test_fun(url):
        with wstest.connect("client", url) as tc:
           ack = tc.hello_v1("/test/topic")
           print(ack)

           tc.send_json(wstest.build_event_v1("/test/topic", "ping", ["hello"]))

    if __name__ == "__main__":
        wstest.main(test_fun, wstest.WS4_URL_V1)

The wstest.main() helper will retry running test_fun on ConnectionRefusedError.
"""

import json
import os
import socket
import time
from typing import Any, Callable, Optional, Union

import websockets.sync.client
from websockets.sync.client import ClientConnection

WS_PORT = (
    int(os.environ["WEBSOCKET_PORT"].split("/")[0])
    if "WEBSOCKET_PORT" in os.environ
    else 0
)

# IPv4 non-secure WebSocker URL for version 1
WS4_URL_V1 = f"ws://127.0.0.1:{WS_PORT}/v1/messages/json"
WS6_URL_V1 = f"ws://[::1]:{WS_PORT}/v1/messages/json"

DEFAULT_RECV_TIMEOUT = 0.1
OWN_TOPIC_PREFIX = "/zeek/wstest"

MAIN_TRIES = 200
MAIN_SLEEP = 0.05


class TestClient:
    """
    Helper class wrapping a websockets ClientConnection
    with a bit of convenience.
    """

    def __init__(self, name: str, cc: ClientConnection):
        self.__name = name
        self.__cc = cc
        self.__own_topic = f"{OWN_TOPIC_PREFIX}/{self.name}/"

    def __enter__(self) -> "TestClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.__cc.__exit__(exc_type, exc_value, traceback)

    def hello_v1(self, topics: list[str]):
        self.send_json([self.__own_topic] + topics[:])
        ack = self.recv_json()
        assert "type" in ack, repr(ack)
        assert ack["type"] == "ack", repr(ack)
        assert "endpoint" in ack, repr(ack)
        assert "version" in ack, repr(ack)
        return ack

    def recv_json(self, timeout=DEFAULT_RECV_TIMEOUT) -> dict:
        raw = self.__cc.recv(timeout=timeout)
        return json.loads(raw)

    def send_json(self, data) -> None:
        return self.__cc.send(json.dumps(data))

    @property
    def name(self) -> str:
        return self.__name


def connect(
    name: str,
    url: Optional[str] = None,
    additional_headers: Optional[dict[str, str]] = None,
) -> TestClient:
    """
    Connect to a WebSocket server and return a TestClient instance.
    """
    if url is None:
        url = WS4_URL_V1

    cc = websockets.sync.client.connect(url, additional_headers=additional_headers)
    return TestClient(name, cc)


def recv_until_timeout(
    clients: list[TestClient], *, timeout: float = DEFAULT_RECV_TIMEOUT, desc=None
):
    """
    Read events from all entries in clients, stopping when all timeout,
    otherwise print status messages.
    """
    if desc:
        print(f"recv_until_timeout: {desc}")

    all_timeout = False
    while not all_timeout:
        msgs = []
        all_timeout = True
        for tc in clients:
            data = None
            try:
                data = tc.recv_json(timeout=timeout)
                all_timeout = False
                ev = data["data"][2]["data"]
                info = {
                    "client": tc.name,
                    "topic": data["topic"],
                    "event_name": ev[0]["data"],
                    "event_args": ev[1]["data"],
                }
                msgs += [info]
            except KeyError as e:
                msgs += [{"client": tc.name, "error": repr(e), "data": data}]
            except TimeoutError:
                msgs += [{"client": tc.name, "timeout": True}]

        if not all_timeout:
            for msg in msgs:
                print(json.dumps(msg))


class TypedArg:
    """
    Helper class for V1 event arguments.
    """

    def __init__(self, typ: str, value: Any):
        self.typ = typ
        self.value = value


EventArg = Union[str, int, TypedArg]


def build_event_arg_v1(arg: EventArg):
    """
    Convert arg into a Broker WebSocket v1 dict with keys `@data-type` and `data`.

    This only supports `str`, `int` and `TypedArg` arguments.
    """
    data_type: Union[str, None] = None
    data: Any = None

    if isinstance(arg, int):
        data_type = "count"
        data = arg
    elif isinstance(arg, str):
        data_type = "string"
        data = arg
    elif isinstance(arg, TypedArg):
        data_type = arg.typ
        data = arg.value
    else:
        raise TypeError(f"Unsupported arg {arg!r} of type {type(arg)}")

    return {
        "@data-type": data_type,
        "data": data,
    }


def build_event_v1(
    topic: str, event_name: str, args: Optional[list[EventArg]] = None
) -> dict:
    """
    Build an event for testing using the quirky v1 format.

    Arguments can be whatever is supported by build_event_arg_v1().
    """
    if args is None:
        args = []

    event_args = []

    for arg in args:
        event_args += [build_event_arg_v1(arg)]

    return {
        "type": "data-message",
        "topic": topic,
        "@data-type": "vector",
        "data": [
            {"@data-type": "count", "data": 1},  # Format
            {"@data-type": "count", "data": 1},  # Type
            {
                "@data-type": "vector",
                "data": [  # Event vector
                    {"@data-type": "string", "data": event_name},
                    {"@data-type": "vector", "data": event_args},
                ],
            },
        ],
    }


def main(f: Callable, *args, **kwargs):
    """
    Wrapper to start a test retrying on ConnectionRefusedError.

    This handles ConnectionRefusedError and invokes f after sleeping a bit with
    the assumption that the WebSocket server wasn't yet available.
    """
    for _ in range(MAIN_TRIES):
        try:
            f(*args, **kwargs)
            break
        except ConnectionRefusedError:
            time.sleep(MAIN_SLEEP)


def monkey_patch_close_socket():
    """
    Monkey patch websockets.sync.ClientConnection.close_socket()

    What's commented out from the original implementation is calling
    receive_eof() on self.protocol as well as acknowledge_pending_pings().

    The reason for doing this is that in the scneario where the websockets
    library detects a closed socket during sending, it'll call close_socket()
    which in turn invokes protocol.receive_eof().

    However, when the concurrently running recv_events() thread is racing
    and has just successfully received the server's CLOSE frame, the EOF
    set on protocol results in an EOFError for the receiving thread instead
    of processing the CLOSE frame. It then further reports an
    "unexpected internal error".

    Changing the close_socket() implemenation allows the EOF condition
    to be set only on the receiving side, avoiding the race.
    """

    def __custom_close_socket(self):
        """
        The original implementation is taken from Connection.close_socket()
        in sync/connection.py (version 15.0.1).

        """
        # shutdown() is required to interrupt recv() on Linux.
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # socket is already closed
        self.socket.close()

        # Calling protocol.receive_eof() is safe because it's idempotent.
        # This guarantees that the protocol state becomes CLOSED.
        #
        # Commented out: Let the recv_events() threads do EOF handling.
        #
        # with self.protocol_mutex:
        #    self.protocol.receive_eof()
        #    assert self.protocol.state is CLOSED

        # Abort recv() with a ConnectionClosed exception.
        self.recv_messages.close()

        # Acknowledge pings sent with the ack_on_close option.
        #
        # Commented out: Asserts on protcol.state is CLOSED
        #
        # self.acknowledge_pending_pings()

    ClientConnection.close_socket = __custom_close_socket
