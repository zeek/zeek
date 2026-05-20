import argparse
import asyncio
import dataclasses
import json
import logging
import queue
import threading

import websockets
import zeek_websocket

LOGGER = logging.getLogger("acld")

StopRequest = object()


@dataclasses.dataclass
class PubSubRule:
    ty: str
    arg: str
    rule_id: str
    rule: zeek_websocket.Value


@dataclasses.dataclass
class AddRules:
    pubsub_id: int
    rules: list[PubSubRule]


@dataclasses.dataclass
class RemoveRules:
    pubsub_id: int
    rules: list[PubSubRule]


class NullRouteClient:
    def __init__(
        self,
        *,
        request_queue: queue.Queue,
        response_queue: queue.Queue,
        queue_get_timeout: float,
        max_jobs: int = 10,
    ):
        self.request_queue = request_queue
        self.queue_get_timeout = queue_get_timeout
        self.max_jobs = max_jobs
        self.stopped = False

        self.logger = logging.getLogger("acld.nullroute_client")

    def process_jobs(self, jobs: list[AddRules | RemoveRules]):
        """
        Do a POST request, put responses into the response queue (or send
        events directly via WebSocket client, not sure).
        """
        self.logger.info("Processing %d jobs", len(jobs))

        adds: list[PubSubRule] = []
        removes = []

        # Jobs can be AddRules or RemoveRules where each contain
        # a PubSubRule instance, so split them here.
        for j in jobs:
            if isinstance(j, AddRules):
                adds.extend(j.rules)
            elif isinstance(j, RemoveRules):
                removes.extend(j.rules)
            else:
                raise ValueError(f"unhandled {j!r}")

        print("adds: ", ",".join(a.arg for a in adds))

    def run(self):
        """
        Runner of the NullRouteClient.
        """
        self.logger.info("Running!")
        jobs = []
        while not self.stopped:
            timed_out = False
            try:
                job = self.request_queue.get(timeout=self.queue_get_timeout)
                if job is StopRequest:
                    self.stopped = True
                    break

            except queue.Empty:
                self.logger.debug("Timeout!")
                timed_out = True
                if jobs:
                    # submit tasks
                    self.process_jobs(jobs)
            else:
                jobs += [job]

            # How many jobs to dequeue before processing them.
            if jobs and timed_out or len(jobs) >= self.max_jobs:
                self.process_jobs(jobs)
                jobs = []

        self.logger.info("Stopped")

    def stop(self):
        """
        Stop this NullRoute client.
        """
        self.logger.info("Stopping")
        self.stopped = True
        self.request_queue.put_nowait(StopRequest)


ADDED = 0
REMOVED = 1
EXISTS = 2
ERROR = 3

event_names = [
    "NetControl::pubsub_rule_added",
    "NetControl::pubsub_rule_removed",
    "NetControl::pubsub_rule_exists",
    "NetControl::pubsub_rule_error",
]


class Proxy:
    """
    Proxy sits between Zeek and ACLd.

    Receive events from Zeek
      -->     From Zeek to here
          --> From here to HTTP API
          <-- From API to here
      <--     Send events back to Zeek to confirm.
    """

    def __init__(
        self,
        *,
        websocket_client: websockets.ClientConnection,
        nullroute_client: NullRouteClient,
        request_topic: str,
        request_queue: queue.Queue,
        response_queue: queue.Queue,
    ):
        self.websocket_client: websockets.ClientConnection = websocket_client
        self.nullroute_client: NullRouteClient = nullroute_client
        self.request_topic = request_topic
        self.pb = zeek_websocket.ProtocolBinding([self.request_topic])

        self.request_queue = request_queue
        self.response_queue = response_queue

    async def run(self):
        subscriptions = self.pb.outgoing()
        assert subscriptions
        await self.websocket_client.send(subscriptions)
        ack = await self.websocket_client.recv()
        ack = json.loads(ack)
        if ack.get("type") != "ack" or "endpoint" not in ack:
            LOGGER.error("Bad ack received %r", ack)
            raise ValueError(repr(ack))

        LOGGER.info("Got ack %s", ack)

        while True:
            # This client is driven via events from Zeek.
            msg = await self.websocket_client.recv(decode=False)
            # print("GOT MESSAGE!", msg)

            self.pb.handle_incoming(msg)  # Rust rust rust

            topic_event = self.pb.receive_event()
            # print("TE", topic_event)
            if topic_event is not None:
                topic, event = topic_event
                name, args = event.name, event.args
                _ = name
                reply_topic, pubsub_id, rules = args
                # LOGGER.debug("event_name=%s reply_topic=%s rules=%s", name, reply_topic, rules)
                # print("RULES", rules)

                job = AddRules(pubsub_id=pubsub_id.value, rules=[])

                for i, r in enumerate(rules.value):
                    psr = r.as_record(PubSubRule)  # rust rust rust
                    job.rules += [psr]

                self.request_queue.put(job)

                # print("XXX XXX QUEUE SIZE", self.request_queue.qsize())
                # print("pssr", pssr)

                # reply_event = zeek_websocket.Event(
                #    name=event_names[ADDED],
                #    args=[pubsub_id, rule, "done!"],
                #    metadata=[],
                # )

                # self.pb.publish_event(reply_topic.value, reply_event)

                # This can deadlock when we write too much
                # because then the transport is "paused"
                # because probably only continue once we have
                # consumed more bytes.
                # while out := self.pb.outgoing():
                #    await self.websocket_client.send(out, text=True)


def setup_nullroute_client(args, request_queue, response_queue) -> NullRouteClient:
    """
    TODO: Needs an API token and stuff.

    This thing isn't all that special? It just does a POST to /nullroute-bulk
    with a bunch of IPs to block  and gets back an array of statuses that match
    the order of what was passed in?

    There is some

        res = client.post(....)
        res = res.json()
        for add, r in zip(adds, res["result"])
            add["result"] = r["result"]
    """
    return NullRouteClient(
        request_queue=request_queue,
        response_queue=response_queue,
        queue_get_timeout=0.01,
    )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--ws-uri",
        default="ws://127.0.0.1:27759/v1/messages/json",
        help="The URI for Zeek's WebSocket API on the manager",
    )
    parser.add_argument("--ws-open-timeout", type=int, default=10)
    parser.add_argument(
        "--request-topic",
        type=str,
        default="lbl/acld/request",
        help="The topic to subscribe to and listen of NetControl::pubsub_* events",
    )
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    request_queue = queue.Queue()
    response_queue = queue.Queue()
    nullroute_client = setup_nullroute_client(args, request_queue, response_queue)

    nullroute_thread = threading.Thread(target=nullroute_client.run)
    nullroute_thread.start()

    try:
        async with websockets.connect(
            args.ws_uri, open_timeout=args.ws_open_timeout
        ) as ws:
            print("CONNECTED")
            proxy = Proxy(
                websocket_client=ws,
                nullroute_client=nullroute_client,
                request_topic=args.request_topic,
                request_queue=request_queue,
                response_queue=response_queue,
            )
            try:
                await proxy.run()
            except asyncio.exceptions.CancelledError:
                LOGGER.info("Cancelled...")
    finally:
        try:
            nullroute_client.stop()
            nullroute_thread.join()
        except Exception as e:
            LOGGER.exception("Exception shutting down nullroute_client: %s", e)


if __name__ == "__main__":
    asyncio.run(main())
